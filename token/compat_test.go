package token_test

// Golden wire-compatibility gate for the token package.
//
// testdata/golden_tokens.json was minted by this package at commit 572dcaa5b2a0, the version BCM
// and admin_api pin, before the OAuth handshake-cookie change. It pins the claims JSON, the signed
// token strings and the exact Set-Cookie headers Set and Reset emit.
//
// If any assertion here fails, the package is no longer wire-compatible with tokens and cookies
// already issued in production: deploying it signs every logged-in user out and breaks the
// rolling-deploy skew with instances still on the old code. Fix the code, do not regenerate the
// fixtures.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/token"
)

const goldenFilePath = "testdata/golden_tokens.json"

type goldenOpts struct {
	Secret          string `json:"secret"`
	SecureCookies   bool   `json:"secure_cookies"`
	DisableXSRF     bool   `json:"disable_xsrf"`
	DisableIAT      bool   `json:"disable_iat"`
	TokenDuration   int    `json:"token_duration_seconds"`
	CookieDuration  int    `json:"cookie_duration_seconds"`
	JWTCookieName   string `json:"jwt_cookie_name"`
	JWTCookieDomain string `json:"jwt_cookie_domain"`
	XSRFCookieName  string `json:"xsrf_cookie_name"`
	Issuer          string `json:"issuer"`
	SameSite        int    `json:"same_site"`
}

func (o goldenOpts) service() *token.Service {
	return token.NewService(token.Opts{
		SecretReader:    token.SecretFunc(func(string) (string, error) { return o.Secret, nil }),
		SecureCookies:   o.SecureCookies,
		DisableXSRF:     o.DisableXSRF,
		DisableIAT:      o.DisableIAT,
		TokenDuration:   time.Duration(o.TokenDuration) * time.Second,
		CookieDuration:  time.Duration(o.CookieDuration) * time.Second,
		JWTCookieName:   o.JWTCookieName,
		JWTCookieDomain: o.JWTCookieDomain,
		XSRFCookieName:  o.XSRFCookieName,
		Issuer:          o.Issuer,
		SameSite:        http.SameSite(o.SameSite),
	})
}

type goldenTokenCase struct {
	Name         string          `json:"name"`
	Opts         string          `json:"opts"`
	InputClaims  json.RawMessage `json:"input_claims"`
	Token        string          `json:"token"`
	ParsedClaims json.RawMessage `json:"parsed_claims"`
}

type goldenSetCase struct {
	Name           string          `json:"name"`
	Opts           string          `json:"opts"`
	InputClaims    json.RawMessage `json:"input_claims"`
	SetCookie      []string        `json:"set_cookie"`
	ReturnedClaims json.RawMessage `json:"returned_claims"`
}

type goldenResetCase struct {
	Name      string   `json:"name"`
	Opts      string   `json:"opts"`
	SetCookie []string `json:"set_cookie"`
}

type goldenFile struct {
	Opts         map[string]goldenOpts `json:"opts"`
	Tokens       []goldenTokenCase     `json:"tokens"`
	SetCookies   []goldenSetCase       `json:"set_cookies"`
	ResetCookies []goldenResetCase     `json:"reset_cookies"`
}

func (g goldenFile) service(t *testing.T, name string) *token.Service {
	t.Helper()
	o, ok := g.Opts[name]
	require.Truef(t, ok, "golden file has no options profile %q", name)
	return o.service()
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	data, err := os.ReadFile(goldenFilePath)
	require.NoError(t, err)

	var golden goldenFile
	require.NoError(t, json.Unmarshal(data, &golden))
	require.NotEmpty(t, golden.Tokens)
	require.NotEmpty(t, golden.SetCookies)
	require.NotEmpty(t, golden.ResetCookies)
	return golden
}

// claimsFromGolden decodes checked-in claims JSON into the Claims struct.
func claimsFromGolden(t *testing.T, raw json.RawMessage) token.Claims {
	t.Helper()
	var claims token.Claims
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims
}

// assertClaimsMatchGolden compares claims both as a struct and as JSON. The JSON comparison is the
// load-bearing one: it pins the wire field names, so renaming a struct tag on both sides at once
// cannot slip through.
func assertClaimsMatchGolden(t *testing.T, want json.RawMessage, got token.Claims) {
	t.Helper()
	assert.Equal(t, claimsFromGolden(t, want), got)

	gotJSON, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(gotJSON))
}

// TestCompat_ParseGoldenTokens is the read direction: a token string signed by the current
// production code must parse to exactly the claims that code parsed it to.
func TestCompat_ParseGoldenTokens(t *testing.T) {
	golden := loadGolden(t)

	for _, tc := range golden.Tokens {
		t.Run(tc.Name, func(t *testing.T) {
			claims, err := golden.service(t, tc.Opts).Parse(tc.Token)
			require.NoError(t, err, "golden token no longer parses - existing sessions would break")
			assertClaimsMatchGolden(t, tc.ParsedClaims, claims)
		})
	}
}

// TestCompat_MintGoldenTokens is the write direction: the same claims must produce a byte-identical
// signed string, so a token minted by this code is accepted by instances still running the
// old code during a rolling deploy.
func TestCompat_MintGoldenTokens(t *testing.T) {
	golden := loadGolden(t)

	for _, tc := range golden.Tokens {
		t.Run(tc.Name, func(t *testing.T) {
			tokenString, err := golden.service(t, tc.Opts).Token(claimsFromGolden(t, tc.InputClaims))
			require.NoError(t, err)
			assert.Equal(t, tc.Token, tokenString)
		})
	}
}

// TestCompat_SetEmitsGoldenCookies pins the exact Set-Cookie headers Set emits: name, value, Path,
// Domain, Max-Age, HttpOnly, Secure and SameSite.
func TestCompat_SetEmitsGoldenCookies(t *testing.T) {
	golden := loadGolden(t)

	for _, tc := range golden.SetCookies {
		t.Run(tc.Name, func(t *testing.T) {
			w := httptest.NewRecorder()
			claims, err := golden.service(t, tc.Opts).Set(w, claimsFromGolden(t, tc.InputClaims))
			require.NoError(t, err)
			assertClaimsMatchGolden(t, tc.ReturnedClaims, claims)
			assert.Equal(t, tc.SetCookie, w.Result().Header.Values("Set-Cookie"))
		})
	}
}

// TestCompat_ResetEmitsGoldenCookies pins Reset's headers, including the deliberate HttpOnly
// asymmetry with Set (no HttpOnly here, HttpOnly on the JWT cookie there) and the fact that Reset
// emits exactly two cookies.
func TestCompat_ResetEmitsGoldenCookies(t *testing.T) {
	golden := loadGolden(t)

	for _, tc := range golden.ResetCookies {
		t.Run(tc.Name, func(t *testing.T) {
			w := httptest.NewRecorder()
			golden.service(t, tc.Opts).Reset(w)
			assert.Equal(t, tc.SetCookie, w.Result().Header.Values("Set-Cookie"))
		})
	}
}

// TestCompat_GetAcceptsGoldenCookie exercises the real production read path end to end: a browser
// presenting a cookie minted by the current code, with the matching XSRF header, must still
// authenticate.
func TestCompat_GetAcceptsGoldenCookie(t *testing.T) {
	golden := loadGolden(t)

	for _, tc := range golden.Tokens {
		expected := claimsFromGolden(t, tc.ParsedClaims)
		if expected.User == nil {
			continue // handshake tokens are read by the OAuth callback, not the auth middleware
		}
		t.Run(tc.Name, func(t *testing.T) {
			opts, ok := golden.Opts[tc.Opts]
			require.True(t, ok)

			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.AddCookie(&http.Cookie{Name: opts.JWTCookieName, Value: tc.Token})
			r.Header.Set("X-XSRF-TOKEN", expected.Id)

			claims, tokenString, err := opts.service().Get(r)
			require.NoError(t, err, "an existing production cookie must still be accepted")
			assert.Equal(t, tc.Token, tokenString)

			// Get promotes the claim's aud onto the user, Parse does not.
			expected.User.Audience = expected.Audience
			assert.Equal(t, expected, claims)
		})
	}
}
