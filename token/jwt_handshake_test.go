package token

// Tests for the dedicated OAuth handshake cookie. They live in their own file rather than in
// jwt_test.go so the upstream suite stays as close to upstream as possible.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func handshakeTestService() *Service {
	return NewService(Opts{SecretReader: SecretFunc(mockKeyStore), JWTCookieName: "rp-token",
		TokenDuration: time.Hour, CookieDuration: days31})
}

// mintHandshake signs a handshake token with the given state and expiry offset from now.
func mintHandshake(t *testing.T, j *Service, state string, expiresIn time.Duration) string {
	t.Helper()
	tk, err := j.Token(Claims{
		Handshake:      &Handshake{State: state, From: "http://example.com/back"},
		StandardClaims: jwt.StandardClaims{Id: "cid-" + state, ExpiresAt: time.Now().Add(expiresIn).Unix()},
	})
	require.NoError(t, err)
	return tk
}

func cookieNames(w *httptest.ResponseRecorder) []string {
	cookies := w.Result().Cookies()
	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	return names
}

func cookieByName(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestJWT_HandshakeCookieNameIsDerived(t *testing.T) {
	assert.Equal(t, "rp-token-oauth-state", handshakeTestService().handshakeCookieName())
	assert.Equal(t, defaultJWTCookieName+handshakeCookieSuffix, NewService(Opts{}).handshakeCookieName())
	assert.Equal(t, "jc1-oauth-state", NewService(Opts{JWTCookieName: jwtCustomCookieName}).handshakeCookieName())
}

func TestJWT_SetHandshakeCookieAttributes(t *testing.T) {
	j := NewService(Opts{SecretReader: SecretFunc(mockKeyStore), JWTCookieName: "rp-token",
		JWTCookieDomain: "blah.com", SecureCookies: true, SameSite: http.SameSiteStrictMode,
		TokenDuration: time.Hour, CookieDuration: days31})

	w := httptest.NewRecorder()
	require.NoError(t, j.SetHandshake(w, Claims{Handshake: &Handshake{State: "st"},
		StandardClaims: jwt.StandardClaims{Id: "cid"}}))

	cookies := w.Result().Cookies()
	// stage 1 dual-write: the session pair exactly as Set emitted it, then the dedicated cookie
	require.Equal(t, []string{"rp-token", "XSRF-TOKEN", "rp-token-oauth-state"}, cookieNames(w))

	c := cookies[2]
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Secure)
	assert.Equal(t, "/", c.Path)
	assert.Equal(t, "blah.com", c.Domain)
	assert.Equal(t, int(handshakeDuration.Seconds()), c.MaxAge, "MaxAge matches the handshake expiry")
	// deliberate divergence from the session cookie's configurable SameSite: the callback arrives as
	// a cross-site top-level redirect from the identity provider
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite, "the session cookie keeps its own")

	claims, err := j.Parse(c.Value)
	require.NoError(t, err)
	require.NotNil(t, claims.Handshake)
	assert.Equal(t, "st", claims.Handshake.State)
	assert.NotZero(t, claims.ExpiresAt, "expiry is filled in when the caller left it unset")

	// the token is minted once and written to both cookies: two mints would run ClaimsUpd twice and
	// could disagree over iat
	assert.Equal(t, cookies[0].Value, c.Value, "both cookies carry the identical token")
	assert.Equal(t, 0, cookies[0].MaxAge, "a handshake makes the session cookie session-only")
}

func TestJWT_SetHandshakeInsecureCookie(t *testing.T) {
	j := handshakeTestService() // SecureCookies false
	w := httptest.NewRecorder()
	require.NoError(t, j.SetHandshake(w, Claims{Handshake: &Handshake{State: "st"}}))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 3)
	for _, c := range cookies {
		assert.False(t, c.Secure, c.Name)
	}
}

func TestJWT_SetHandshakeRejectsNonHandshakeClaims(t *testing.T) {
	j := handshakeTestService()
	w := httptest.NewRecorder()
	err := j.SetHandshake(w, Claims{User: &User{ID: "u1"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a handshake token")
	assert.Empty(t, w.Result().Cookies())
}

func TestJWT_SetHandshakeSigningFailure(t *testing.T) {
	j := NewService(Opts{}) // no secret reader
	w := httptest.NewRecorder()
	err := j.SetHandshake(w, Claims{Handshake: &Handshake{State: "st"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to make handshake token")
	assert.Empty(t, w.Result().Cookies())
}

// TestJWT_SetHandshakeStampsExpiry: SetHandshake owns the handshake lifetime, it does not merely
// default it. A caller presetting a longer exp would otherwise get a token outliving the cookie that
// carries it, and GetHandshake trusts exp rather than the cookie's MaxAge.
func TestJWT_SetHandshakeStampsExpiry(t *testing.T) {
	j := handshakeTestService()
	w := httptest.NewRecorder()

	require.NoError(t, j.SetHandshake(w, Claims{Handshake: &Handshake{State: "st"},
		StandardClaims: jwt.StandardClaims{Id: "cid", ExpiresAt: time.Now().Add(72 * time.Hour).Unix()}}))

	c := cookieByName(w, j.handshakeCookieName())
	require.NotNil(t, c)
	claims, err := j.Parse(c.Value)
	require.NoError(t, err)

	latest := time.Now().Add(handshakeDuration).Unix()
	assert.LessOrEqual(t, claims.ExpiresAt, latest, "the caller's longer expiry is overridden")
	assert.Greater(t, claims.ExpiresAt, latest-60, "and it is still a full handshake lifetime")
	assert.Equal(t, int(handshakeDuration.Seconds()), c.MaxAge, "token and cookie retire together")
}

func TestJWT_ResetHandshakeAttributes(t *testing.T) {
	j := handshakeTestService()
	w := httptest.NewRecorder()
	j.ResetHandshake(w)

	assert.Equal(t, []string{
		"rp-token-oauth-state=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Lax",
	}, w.Result().Header.Values("Set-Cookie"), "ResetHandshake clears only the handshake cookie")
}

// TestJWT_SetAndResetIgnoreHandshakeCookie is the load-bearing one: Set is called by the middleware's
// refresh path and Reset by its validator-rejection and refresh-failure paths, so if either touched
// the handshake cookie a concurrent unrelated request could still destroy an in-flight login.
func TestJWT_SetAndResetIgnoreHandshakeCookie(t *testing.T) {
	j := handshakeTestService()

	w := httptest.NewRecorder()
	_, err := j.Set(w, Claims{User: &User{ID: "u1"}, StandardClaims: jwt.StandardClaims{Id: "cid"}})
	require.NoError(t, err)
	setNames := cookieNames(w)
	assert.Equal(t, []string{"rp-token", "XSRF-TOKEN"}, setNames)
	assert.NotContains(t, setNames, j.handshakeCookieName())

	w = httptest.NewRecorder()
	j.Reset(w)
	resetNames := cookieNames(w)
	assert.Equal(t, []string{"rp-token", "XSRF-TOKEN"}, resetNames)
	assert.NotContains(t, resetNames, j.handshakeCookieName())
}

func TestJWT_GetHandshakeFromDedicatedCookie(t *testing.T) {
	j := handshakeTestService()
	r := httptest.NewRequest("GET", "/callback?state=st", http.NoBody)
	r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: mintHandshake(t, j, "st", time.Minute)})

	claims, err := j.GetHandshake(r, "st")
	require.NoError(t, err)
	require.NotNil(t, claims.Handshake)
	assert.Equal(t, "st", claims.Handshake.State)
	assert.Equal(t, "http://example.com/back", claims.Handshake.From)
}

// TestJWT_GetHandshakeFromLegacyCookie covers the old-login -> new-callback rollout direction: a
// login served by an instance running the old code only wrote the handshake to the session cookie.
func TestJWT_GetHandshakeFromLegacyCookie(t *testing.T) {
	j := handshakeTestService()
	r := httptest.NewRequest("GET", "/callback?state=st", http.NoBody)
	r.AddCookie(&http.Cookie{Name: j.JWTCookieName, Value: mintHandshake(t, j, "st", time.Minute)})

	claims, err := j.GetHandshake(r, "st")
	require.NoError(t, err)
	require.NotNil(t, claims.Handshake)
	assert.Equal(t, "st", claims.Handshake.State)
}

// TestJWT_GetHandshakeSelectsByStateNotPresence is why the read is not "new cookie, else fall back":
// an abandoned new-code login leaves a live handshake in the dedicated cookie that would otherwise
// mask the legacy handshake the callback actually belongs to.
func TestJWT_GetHandshakeSelectsByStateNotPresence(t *testing.T) {
	j := handshakeTestService()

	t.Run("stale dedicated cookie, valid legacy cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/callback?state=wanted", http.NoBody)
		r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: mintHandshake(t, j, "abandoned", time.Minute)})
		r.AddCookie(&http.Cookie{Name: j.JWTCookieName, Value: mintHandshake(t, j, "wanted", time.Minute)})

		claims, err := j.GetHandshake(r, "wanted")
		require.NoError(t, err)
		assert.Equal(t, "wanted", claims.Handshake.State)
	})

	t.Run("valid dedicated cookie, clobbered legacy cookie", func(t *testing.T) {
		// this is the production bug: a concurrent refresh replaced the session cookie with user claims
		w := httptest.NewRecorder()
		_, err := j.Set(w, Claims{User: &User{ID: "u1"}, StandardClaims: jwt.StandardClaims{Id: "cid"}})
		require.NoError(t, err)

		r := httptest.NewRequest("GET", "/callback?state=wanted", http.NoBody)
		r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: mintHandshake(t, j, "wanted", time.Minute)})
		for _, c := range w.Result().Cookies() {
			r.AddCookie(c)
		}

		claims, err := j.GetHandshake(r, "wanted")
		require.NoError(t, err)
		assert.Equal(t, "wanted", claims.Handshake.State)
	})

	t.Run("neither matches", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/callback?state=wanted", http.NoBody)
		r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: mintHandshake(t, j, "other1", time.Minute)})
		r.AddCookie(&http.Cookie{Name: j.JWTCookieName, Value: mintHandshake(t, j, "other2", time.Minute)})

		_, err := j.GetHandshake(r, "wanted")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrHandshakeStateMismatch))
	})
}

// TestJWT_GetHandshakeRejectsExpired pins the server-side expiry check. Parse deliberately tolerates
// expired tokens and MaxAge is only a client-side hint, so the cookie is handed over directly here
// rather than through a cookie jar, which would have discarded it and made the test vacuous.
func TestJWT_GetHandshakeRejectsExpired(t *testing.T) {
	j := handshakeTestService()

	expired := mintHandshake(t, j, "st", -time.Minute)
	// sanity: the token itself still parses and carries the right state, so only the explicit check
	// stands between a replayed handshake and a successful callback
	parsed, err := j.Parse(expired)
	require.NoError(t, err, "Parse allows expired tokens by design")
	assert.Equal(t, "st", parsed.Handshake.State)

	t.Run("dedicated cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/callback?state=st", http.NoBody)
		r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: expired})
		_, err := j.GetHandshake(r, "st")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrHandshakeExpired))
	})

	t.Run("legacy cookie", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/callback?state=st", http.NoBody)
		r.AddCookie(&http.Cookie{Name: j.JWTCookieName, Value: expired})
		_, err := j.GetHandshake(r, "st")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrHandshakeExpired))
	})

	t.Run("expired dedicated cookie does not hide a live legacy one", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/callback?state=st", http.NoBody)
		r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: expired})
		r.AddCookie(&http.Cookie{Name: j.JWTCookieName, Value: mintHandshake(t, j, "st", time.Minute)})
		claims, err := j.GetHandshake(r, "st")
		require.NoError(t, err)
		assert.Equal(t, "st", claims.Handshake.State)
	})
}

func TestJWT_GetHandshakeErrors(t *testing.T) {
	j := handshakeTestService()
	userTok, err := j.Token(Claims{User: &User{ID: "u1"},
		StandardClaims: jwt.StandardClaims{Id: "cid", ExpiresAt: time.Now().Add(time.Hour).Unix()}})
	require.NoError(t, err)

	// notWant is load-bearing for the "nothing was examined" cases: the callback clears the handshake
	// cookie on ErrHandshakeInvalid, so a case where no candidate existed must not carry that
	// sentinel, or an unauthenticated request with no cookies could destroy a login in flight.
	tbl := []struct {
		name    string
		state   string
		cookies map[string]string
		want    error
		notWant error
		wantMsg string
	}{
		{"no cookies at all", "st", nil,
			ErrNoHandshake, ErrHandshakeInvalid, "rp-token-oauth-state cookie was not presented"},
		{"empty state query", "", map[string]string{"rp-token-oauth-state": mintHandshake(t, j, "st", time.Minute)},
			ErrNoHandshake, ErrHandshakeInvalid, "empty state"},
		{"empty cookie value", "st", map[string]string{"rp-token-oauth-state": ""},
			ErrNoHandshake, ErrHandshakeInvalid, "rp-token-oauth-state cookie was not presented"},
		{"user token, not a handshake", "st", map[string]string{"rp-token": userTok},
			ErrHandshakeInvalid, nil, "rp-token does not hold a handshake"},
		{"unparseable token", "st", map[string]string{"rp-token-oauth-state": "not-a-jwt"},
			ErrHandshakeInvalid, nil, "rp-token-oauth-state: can't parse token"},
		{"tampered signature", "st", map[string]string{"rp-token-oauth-state": testJwtBadSign},
			ErrHandshakeInvalid, nil, "rp-token-oauth-state: can't parse token: signature is invalid"},
		{"state mismatch", "st", map[string]string{"rp-token-oauth-state": mintHandshake(t, j, "other", time.Minute)},
			ErrHandshakeStateMismatch, nil, "handshake state mismatch: rp-token-oauth-state"},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/callback", http.NoBody)
			for name, val := range tt.cookies {
				r.AddCookie(&http.Cookie{Name: name, Value: val})
			}
			_, err := j.GetHandshake(r, tt.state)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.want), "got %v", err)
			if tt.notWant != nil {
				assert.False(t, errors.Is(err, tt.notWant), "no candidate was examined, got %v", err)
			}
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

// TestJWT_GetHandshakeBothCookiesFailDifferently: the joined error carries a sentinel per candidate,
// and the callback's switch decides on the first arm that matches, not on cookie order. State
// mismatch wins deliberately: it is the only rejection that may mean "someone else's live login".
func TestJWT_GetHandshakeBothCookiesFailDifferently(t *testing.T) {
	j := handshakeTestService()

	r := httptest.NewRequest("GET", "/callback?state=wanted", http.NoBody)
	r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: mintHandshake(t, j, "wanted", -time.Minute)})
	r.AddCookie(&http.Cookie{Name: j.JWTCookieName, Value: mintHandshake(t, j, "other", time.Minute)})

	_, err := j.GetHandshake(r, "wanted")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHandshakeExpired), "the dedicated cookie's reason survives: %v", err)
	assert.True(t, errors.Is(err, ErrHandshakeStateMismatch), "and so does the legacy cookie's: %v", err)
	assert.Contains(t, err.Error(), "; ", "both verdicts are reported")
}

// TestJWT_GetHandshakeIgnoresXSRF is the point of the whole change: unlike Get, reading a handshake
// never demands an X-XSRF-TOKEN header, which a top-level redirect back from the identity provider
// can never carry.
func TestJWT_GetHandshakeIgnoresXSRF(t *testing.T) {
	j := handshakeTestService()
	r := httptest.NewRequest("GET", "/callback?state=st", http.NoBody)
	r.AddCookie(&http.Cookie{Name: j.handshakeCookieName(), Value: mintHandshake(t, j, "st", time.Minute)})
	assert.Empty(t, r.Header.Get(j.XSRFHeaderKey))

	_, err := j.GetHandshake(r, "st")
	require.NoError(t, err)
}
