package provider

// Tests for the dedicated OAuth handshake cookie, kept out of oauth2_test.go so the upstream suite
// stays as close to upstream as possible.
//
// Background: LoginHandler used to store the oauth2 handshake in the *session* cookie only. Any
// unrelated in-flight request whose token had aged past TokenDuration made the auth middleware
// refresh that cookie, overwriting the handshake with user claims. The callback then read a cookie
// with claims.User != nil, which makes Get demand an X-XSRF-TOKEN header that a top-level redirect
// back from the identity provider can never carry: 500 "failed to get token" on 26% of logins.
//
// The fixture's mock userinfo endpoint answers at most two calls per prepOauth2Test, so no test
// below completes more than two callbacks between prep and teardown.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/token"
)

// handshakeCookie is the dedicated handshake cookie name derived from the fixture's default "JWT"
const handshakeCookie = "JWT-oauth-state"

// doLogin drives LoginHandler on the package-level fixture and returns the cookies it wrote plus
// the state it minted.
func doLogin(t *testing.T, query string) (cookies []*http.Cookie, state string) {
	t.Helper()

	w := httptest.NewRecorder()
	provider.LoginHandler(w, httptest.NewRequest("GET", "/login"+query, http.NoBody))
	require.Equal(t, http.StatusFound, w.Code)

	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	state = loc.Query().Get("state")
	require.NotEmpty(t, state)

	return w.Result().Cookies(), state
}

// jwtService exposes the fixture's concrete token service for minting fixtures
func jwtService(t *testing.T) *token.Service {
	t.Helper()
	svc, ok := provider.JwtService.(*token.Service)
	require.True(t, ok)
	return svc
}

func cookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// assertHandshakeRetired checks c is a deletion of the handshake cookie
func assertHandshakeRetired(t *testing.T, c *http.Cookie) {
	t.Helper()
	require.NotNil(t, c, "handshake cookie must be cleared on this path")
	assert.Equal(t, handshakeCookie, c.Name)
	assert.Empty(t, c.Value)
	assert.Negative(t, c.MaxAge)
}

func assertHandshakeCleared(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assertHandshakeRetired(t, cookieByName(w.Result().Cookies(), handshakeCookie))
}

func assertHandshakeUntouched(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Nil(t, cookieByName(w.Result().Cookies(), handshakeCookie),
		"handshake cookie must be left alone on this path")
}

// TestOauth2CallbackSurvivesConcurrentSessionRefresh is the regression test for the production bug:
// a concurrent request refreshes the session cookie between login and callback, and the callback
// must still complete.
func TestOauth2CallbackSurvivesConcurrentSessionRefresh(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	loginCookies, state := doLogin(t, "?site=remark")

	// a concurrent, unrelated request whose token has aged past TokenDuration: the auth middleware
	// refreshes it, which calls Set and rewrites the session cookie with user claims
	refresh := httptest.NewRecorder()
	_, err := provider.JwtService.Set(refresh, token.Claims{
		User:           &token.User{ID: "mock_myuser1", Name: "someone"},
		StandardClaims: jwt.StandardClaims{Id: "refreshed-cid"},
	})
	require.NoError(t, err)
	refreshed := refresh.Result().Cookies()
	require.Equal(t, "JWT", refreshed[0].Name)

	// the browser now holds the refreshed session cookies plus the handshake cookie (if the login
	// wrote one), and carries no XSRF header because this is a top-level redirect back from the provider
	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	for _, c := range refreshed {
		req.AddCookie(c)
	}
	if c := cookieByName(loginCookies, handshakeCookie); c != nil {
		req.AddCookie(c)
	}
	assert.Empty(t, req.Header.Get("X-XSRF-TOKEN"))

	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code, "callback must survive the session refresh: %s", w.Body.String())

	u := token.User{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &u))
	assert.Equal(t, "mock_myuser1", u.ID)
	assertHandshakeCleared(t, w)
}

// TestHandshakeSurvivesConcurrentReset covers the other half of the coupling: the auth middleware
// calls Reset on validator rejection and on refresh failure, so if Reset also cleared the handshake
// a concurrent *failing* request would destroy an in-flight login.
func TestHandshakeSurvivesConcurrentReset(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	// a concurrent request fails validation; the middleware resets the session cookies
	reset := httptest.NewRecorder()
	provider.JwtService.Reset(reset)
	resetCookies := reset.Result().Cookies()
	require.Len(t, resetCookies, 2, "Reset stays session-only")
	assert.Nil(t, cookieByName(resetCookies, handshakeCookie))

	// the browser applies the cleared session cookies and keeps the handshake cookie
	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	for _, c := range resetCookies {
		req.AddCookie(c)
	}
	req.AddCookie(cookieByName(cookies, handshakeCookie))

	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code, "the in-flight login is unharmed: %s", w.Body.String())
}

// TestOauth2LoginDualWritesHandshake pins stage 1 of the rollout: the handshake goes to the dedicated
// cookie *and* to the session cookie, so a login served by a new instance can have its callback
// served by an old one mid-deploy.
func TestOauth2LoginDualWritesHandshake(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark&from=http://example.com/back")
	require.Len(t, cookies, 3)

	for _, name := range []string{"JWT", handshakeCookie} {
		c := cookieByName(cookies, name)
		require.NotNil(t, c, name)
		claims, err := provider.JwtService.Parse(c.Value)
		require.NoError(t, err, name)
		require.NotNil(t, claims.Handshake, "%s must carry the handshake", name)
		assert.Equal(t, state, claims.Handshake.State, name)
		assert.Equal(t, "http://example.com/back", claims.Handshake.From, name)
		assert.Equal(t, "mock", claims.Provider, name)
	}

	// the same token string, not merely equivalent claims: it is minted once, so a re-defaulted iat
	// or exp cannot make the two copies drift apart
	assert.Equal(t, cookieByName(cookies, "JWT").Value, cookieByName(cookies, handshakeCookie).Value)
}

func TestOauth2LoginHandshakeCookieAttributes(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, _ := doLogin(t, "?site=remark")
	c := cookieByName(cookies, handshakeCookie)
	require.NotNil(t, c)

	assert.True(t, c.HttpOnly)
	assert.False(t, c.Secure, "SecureCookies is off in this fixture")
	assert.Equal(t, "/", c.Path)
	assert.Equal(t, int(time.Hour.Seconds()), c.MaxAge,
		"cookie MaxAge and the exp claim come from token's handshakeDuration")
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite,
		"Lax so the cookie survives the cross-site top-level redirect back from the provider")

	claims, err := provider.JwtService.Parse(c.Value)
	require.NoError(t, err)
	assert.InDelta(t, time.Now().Add(time.Hour).Unix(), claims.ExpiresAt, 5,
		"the handshake lifetime is stamped by SetHandshake, not LoginHandler")
}

func TestOauth2LoginHandshakeSetFailure(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	broken := provider
	broken.JwtService = &brokenHandshakeTokenService{Service: jwtService(t)}

	w := httptest.NewRecorder()
	broken.LoginHandler(w, httptest.NewRequest("GET", "/login", http.NoBody))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to set token"}`, w.Body.String())
}

type brokenHandshakeTokenService struct {
	*token.Service
}

func (b *brokenHandshakeTokenService) SetHandshake(http.ResponseWriter, token.Claims) error {
	return io.ErrClosedPipe
}

func TestOauth2CallbackHappyPathClearsHandshake(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assertHandshakeCleared(t, w)
	assert.NotEmpty(t, cookieByName(w.Result().Cookies(), "JWT").Value, "session cookie still written")
}

func TestOauth2CallbackHandshakeRejections(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()
	svc := jwtService(t)

	live := func(state string) string {
		tk, err := svc.Token(token.Claims{
			Handshake:      &token.Handshake{State: state},
			StandardClaims: jwt.StandardClaims{Id: "cid", ExpiresAt: time.Now().Add(time.Hour).Unix()},
		})
		require.NoError(t, err)
		return tk
	}
	expired, err := svc.Token(token.Claims{
		Handshake:      &token.Handshake{State: "wanted"},
		StandardClaims: jwt.StandardClaims{Id: "cid", ExpiresAt: time.Now().Add(-time.Minute).Unix()},
	})
	require.NoError(t, err)
	userTok, err := svc.Token(token.Claims{
		User:           &token.User{ID: "u1"},
		StandardClaims: jwt.StandardClaims{Id: "cid", ExpiresAt: time.Now().Add(time.Hour).Unix()},
	})
	require.NoError(t, err)

	tbl := []struct {
		name    string
		cookies map[string]string
		msg     string
		// only a candidate that was examined and condemned is cleared. A state mismatch may mean
		// "another login of this user's is still in flight" (the cookie is a single slot, so clearing
		// it would kill that login too) and a request that presented no cookie at all examined
		// nothing, so it must not be able to delete one the browser still holds.
		cleared bool
	}{
		{"missing state cookie", nil, "no handshake token", false},
		{"session cookie only, no handshake in it", map[string]string{"JWT": userTok}, "invalid handshake token", true},
		{"state mismatch", map[string]string{handshakeCookie: live("other")}, "unexpected state", false},
		{"expired handshake", map[string]string{handshakeCookie: expired}, "expired handshake token", true},
		{"garbage cookie", map[string]string{handshakeCookie: "not-a-jwt"}, "invalid handshake token", true},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/callback?code=abc&state=wanted", http.NoBody)
			for name, val := range tt.cookies {
				req.AddCookie(&http.Cookie{Name: name, Value: val})
			}
			w := httptest.NewRecorder()
			provider.AuthHandler(w, req)

			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.JSONEq(t, `{"error":"`+tt.msg+`"}`, w.Body.String())
			if tt.cleared {
				assertHandshakeCleared(t, w)
				return
			}
			assertHandshakeUntouched(t, w)
		})
	}
}

// TestOauth2CallbackExpiredHandshakeSentDirectly pins the server-side expiry check end to end. The
// cookie is handed to the handler directly rather than through a cookie jar: a jar would honour the
// MaxAge and drop it, and the test would pass without the check existing.
func TestOauth2CallbackExpiredHandshakeSentDirectly(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")
	c := cookieByName(cookies, handshakeCookie)
	require.NotNil(t, c)

	// re-sign the very same handshake claims with an exp in the past
	claims, err := provider.JwtService.Parse(c.Value)
	require.NoError(t, err)
	claims.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	expired, err := jwtService(t).Token(claims)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	req.AddCookie(&http.Cookie{Name: handshakeCookie, Value: expired})
	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.JSONEq(t, `{"error":"expired handshake token"}`, w.Body.String())
	assertHandshakeCleared(t, w)
}

// TestOauth2CallbackMismatchKeepsConcurrentLoginAlive is the two-tab case. Tab A and tab B both
// start a login; B's handshake is the one in the cookie. When A's callback comes back it cannot
// match, and if that rejection cleared the single-slot cookie it would take B's live login with it.
func TestOauth2CallbackMismatchKeepsConcurrentLoginAlive(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	_, stateA := doLogin(t, "?site=remark")
	tabB, stateB := doLogin(t, "?site=remark")
	require.NotEqual(t, stateA, stateB)

	// the browser holds only the newest handshake cookie, B's
	stale := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+stateA, http.NoBody)
	stale.AddCookie(cookieByName(tabB, handshakeCookie))
	w := httptest.NewRecorder()
	provider.AuthHandler(w, stale)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"error":"unexpected state"}`, w.Body.String())
	assertHandshakeUntouched(t, w)

	// B now completes, using the cookie A's failed callback left alone
	good := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+stateB, http.NoBody)
	good.AddCookie(cookieByName(tabB, handshakeCookie))
	w = httptest.NewRecorder()
	provider.AuthHandler(w, good)
	require.Equal(t, http.StatusOK, w.Code, "the surviving login must still complete: %s", w.Body.String())
}

// TestOauth2CallbackMismatchWinsOverInvalidSessionCookie pins the switch-arm *order*. GetHandshake
// joins the verdicts of both candidates, so the everyday case (a logged-in user with an ordinary
// session token in the session cookie and a live handshake in the dedicated one, called back with a
// state that does not match) arrives as StateMismatch AND Invalid at once. Only the fact that the
// StateMismatch arm is tested first stops the Invalid arm from clearing that live handshake.
func TestOauth2CallbackMismatchWinsOverInvalidSessionCookie(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	// the user is already logged in: the session cookie holds an ordinary user token, which is a
	// condemned candidate (it holds no handshake) rather than merely absent
	session := httptest.NewRecorder()
	_, err := provider.JwtService.Set(session, token.Claims{
		User:           &token.User{ID: "mock_myuser1", Name: "someone"},
		StandardClaims: jwt.StandardClaims{Id: "session-cid"},
	})
	require.NoError(t, err)

	foreign := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state=someone-elses-state", http.NoBody)
	foreign.AddCookie(cookieByName(session.Result().Cookies(), "JWT"))
	foreign.AddCookie(cookieByName(cookies, handshakeCookie))
	w := httptest.NewRecorder()
	provider.AuthHandler(w, foreign)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"error":"unexpected state"}`, w.Body.String(),
		"the least-destructive verdict must win over the session cookie's")
	assertHandshakeUntouched(t, w)

	// and the login the user actually has in flight still completes
	good := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	good.AddCookie(cookieByName(cookies, handshakeCookie))
	w = httptest.NewRecorder()
	provider.AuthHandler(w, good)
	require.Equal(t, http.StatusOK, w.Code, "the in-flight login must survive: %s", w.Body.String())
}

// TestOauth2CallbackNoStateKeepsHandshakeAlive: GetHandshake short-circuits on an empty state before
// it reads any cookie, so a bare GET /callback, which anyone can make a victim's browser issue
// cross-site and which carries no usable handshake by definition, must not land in an arm that
// clears the cookie and kills whatever login is in flight.
func TestOauth2CallbackNoStateKeepsHandshakeAlive(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	// the browser is holding a live handshake and is sent to the callback with no state at all
	bare := httptest.NewRequest("GET", "/callback", http.NoBody)
	bare.AddCookie(cookieByName(cookies, handshakeCookie))
	w := httptest.NewRecorder()
	provider.AuthHandler(w, bare)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"error":"no handshake token"}`, w.Body.String())
	assertHandshakeUntouched(t, w)

	// and the real callback still completes off the cookie that probe left alone
	good := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	good.AddCookie(cookieByName(cookies, handshakeCookie))
	w = httptest.NewRecorder()
	provider.AuthHandler(w, good)
	require.Equal(t, http.StatusOK, w.Code, "the in-flight login must survive the probe: %s", w.Body.String())
}

// TestOauth2CallbackNoCookieKeepsHandshakeAlive is the same hole reached the other way: a request
// that presents no cookie at all. Nothing about such a request says the browser holds no live
// handshake (the cookie may simply not have been sent) so the reply must not carry a delete for it.
func TestOauth2CallbackNoCookieKeepsHandshakeAlive(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	probe := httptest.NewRequest("GET", "/callback?code=abc&state=guessed", http.NoBody) // no cookies
	w := httptest.NewRecorder()
	provider.AuthHandler(w, probe)

	require.Equal(t, http.StatusForbidden, w.Code)
	assertHandshakeUntouched(t, w)

	good := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	good.AddCookie(cookieByName(cookies, handshakeCookie))
	w = httptest.NewRecorder()
	provider.AuthHandler(w, good)
	require.Equal(t, http.StatusOK, w.Code, "the in-flight login must survive the probe: %s", w.Body.String())
}

// TestOauth2CallbackRejectsOtherProvidersHandshake: /auth/{provider}/callback must only redeem a
// handshake minted by its own /auth/{provider}/login. The code exchange would fail anyway against a
// different client_id, but this is the CSRF boundary and the failure should say so.
func TestOauth2CallbackRejectsOtherProvidersHandshake(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	other, err := jwtService(t).Token(token.Claims{
		Handshake:      &token.Handshake{State: "wanted"},
		Provider:       "another-provider",
		StandardClaims: jwt.StandardClaims{Id: "cid", ExpiresAt: time.Now().Add(time.Hour).Unix()},
	})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/callback?code=abc&state=wanted", http.NoBody)
	req.AddCookie(&http.Cookie{Name: handshakeCookie, Value: other})
	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.JSONEq(t, `{"error":"unexpected provider"}`, w.Body.String())
	// left alone, exactly as a state mismatch is: the handshake is live and it is the user's, it just
	// belongs to a login started at another provider that may still complete at its own callback
	assertHandshakeUntouched(t, w)
}

// TestOauth2CallbackRedirectsToFrom covers the shape production logins actually take: they all carry
// ?from=, so the callback ends in a 307 rather than a JSON body, with the handshake retired first.
func TestOauth2CallbackRedirectsToFrom(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark&from=http://example.com/back")

	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusTemporaryRedirect, w.Code, w.Body.String())
	assert.Equal(t, "http://example.com/back", w.Header().Get("Location"))
	assertHandshakeCleared(t, w)
	assert.NotEmpty(t, cookieByName(w.Result().Cookies(), "JWT").Value,
		"the session cookie is still written before the redirect")
}

// TestOauth2CallbackSetFailureClearsHandshake covers the last terminal path of the callback: the
// handshake was consumed, so it must be retired even though writing the session token failed.
func TestOauth2CallbackSetFailureClearsHandshake(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	broken := provider
	broken.JwtService = &brokenSetTokenService{Service: jwtService(t)}

	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	broken.AuthHandler(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"failed to set token"}`, w.Body.String())
	assertHandshakeCleared(t, w)
}

type brokenSetTokenService struct {
	*token.Service
}

func (b *brokenSetTokenService) Set(http.ResponseWriter, token.Claims) (token.Claims, error) {
	return token.Claims{}, io.ErrClosedPipe
}

func TestOauth2CallbackExchangeFailureClearsHandshake(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	// point the token endpoint at a dead address so Exchange fails
	provider.conf.Endpoint.TokenURL = "http://127.0.0.1:1/login/oauth/access_token"

	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.JSONEq(t, `{"error":"exchange failed"}`, w.Body.String())
	assertHandshakeCleared(t, w)
}

// --- rolling-deploy skew ---------------------------------------------------------------------

// TestOauth2CallbackSkewOldLoginNewCallback: the login was served by an instance running the old
// code, which only wrote the handshake to the session cookie.
func TestOauth2CallbackSkewOldLoginNewCallback(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	req.AddCookie(cookieByName(cookies, "JWT")) // dedicated cookie deliberately withheld
	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// TestOauth2CallbackSkewNewLoginOldCallback: the callback lands on an instance still running the old
// code, which reads the handshake out of the session cookie via Get. The dual-write is what keeps
// that working, so the assertion is that the session cookie a new LoginHandler writes is still
// exactly what the old callback expects to find.
func TestOauth2CallbackSkewNewLoginOldCallback(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	cookies, state := doLogin(t, "?site=remark")

	oldStyle := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	oldStyle.AddCookie(cookieByName(cookies, "JWT"))

	// this is verbatim what the old AuthHandler did before reaching the code exchange
	claims, _, err := provider.JwtService.Get(oldStyle)
	require.NoError(t, err, "an old instance must still find the handshake in the session cookie")
	require.NotNil(t, claims.Handshake)
	assert.Equal(t, state, claims.Handshake.State)
}

// TestOauth2CallbackSkewStaleDedicatedCookie: an abandoned new-code login left a live handshake in
// the dedicated cookie; a later old-code login put the real one in the session cookie. Selecting by
// presence would pick the stale one and fail the state check.
func TestOauth2CallbackSkewStaleDedicatedCookie(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	abandoned, _ := doLogin(t, "?site=remark")
	current, state := doLogin(t, "?site=remark")

	req := httptest.NewRequest("GET", "/callback?code=g0ZGZmNjVmOWI&state="+state, http.NoBody)
	req.AddCookie(cookieByName(abandoned, handshakeCookie)) // stale
	req.AddCookie(cookieByName(current, "JWT"))             // valid, legacy location
	w := httptest.NewRecorder()
	provider.AuthHandler(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// --- logout ----------------------------------------------------------------------------------

func TestOauth2LogoutClearsHandshake(t *testing.T) {
	teardown := prepOauth2Test(t, 8981, 8982)
	defer teardown()

	t.Run("valid session", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/logout", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: testJwtValid})
		req.Header.Set("X-XSRF-TOKEN", "random id")
		w := httptest.NewRecorder()
		provider.LogoutHandler(w, req)

		require.Equal(t, http.StatusNoContent, w.Code)
		assertHandshakeCleared(t, w)
		assert.Empty(t, cookieByName(w.Result().Cookies(), "JWT").Value, "session cookie cleared too")
	})

	// LogoutHandler answers 403 and returns early when the session cookie is missing or unreadable.
	// That is exactly when a user is trying to escape a broken session, so the handshake cookie must
	// already have been cleared before that check.
	t.Run("missing session cookie", func(t *testing.T) {
		w := httptest.NewRecorder()
		provider.LogoutHandler(w, httptest.NewRequest("GET", "/logout", http.NoBody))

		require.Equal(t, http.StatusForbidden, w.Code)
		assertHandshakeCleared(t, w)
	})

	t.Run("invalid session cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/logout", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: "not-a-jwt"})
		w := httptest.NewRecorder()
		provider.LogoutHandler(w, req)

		require.Equal(t, http.StatusForbidden, w.Code)
		assertHandshakeCleared(t, w)
	})
}
