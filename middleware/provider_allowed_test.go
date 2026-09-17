package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/token"
)

func TestIsProviderAllowed(t *testing.T) {
	a := makeTestAuth(t) // registers provider1, provider2 and the mock refreshable provider

	tbl := []struct {
		name     string
		provider string
		userID   string
		want     bool
	}{
		// the prov claim decides when present
		{"prov registered, native subject id", "provider1", "a1b2c3d4-0000-4000-8000-000000000001", true},
		{"prov registered, prefixed id", "provider2", "provider2_id1", true},
		{"prov unregistered, prefixed id names a registered provider", "provider3", "provider1_id1", false},
		{"prov unregistered, native subject id", "provider3", "a1b2c3d4-0000-4000-8000-000000000001", false},
		// legacy tokens without a prov claim fall back to the id prefix
		{"no prov, registered prefix", "", "provider1_id1", true},
		{"no prov, unregistered prefix", "", "provider3_id1", false},
		{"no prov, native subject id", "", "a1b2c3d4-0000-4000-8000-000000000001", false},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			claims := token.Claims{User: &token.User{ID: tt.userID}, Provider: tt.provider}
			assert.Equal(t, tt.want, a.isProviderAllowed(claims))
		})
	}
}

// TestAuthProviderCheckUsesProvClaim runs the check through the middleware: a token whose user ID
// carries no provider prefix must still be accepted when its prov claim names a registered provider,
// and a prov claim naming an unregistered provider is rejected even when the ID prefix looks fine.
func TestAuthProviderCheckUsesProvClaim(t *testing.T) {
	a := makeTestAuth(t)

	mux := http.NewServeMux()
	mux.Handle("/auth", a.Auth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})))
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{Timeout: 5 * time.Second}

	mint := func(t *testing.T, prov, userID string) string {
		t.Helper()
		tk, err := a.JWTService.(*token.Service).Token(token.Claims{
			User:     &token.User{Name: "name1", ID: userID},
			Provider: prov,
			StandardClaims: jwt.StandardClaims{Id: "random id", Audience: "test_sys",
				ExpiresAt: time.Now().Add(time.Hour).Unix()},
		})
		require.NoError(t, err)
		return tk
	}

	call := func(t *testing.T, tk string) int {
		t.Helper()
		req, err := http.NewRequest("GET", server.URL+"/auth", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "JWT", Value: tk, HttpOnly: true, Path: "/"})
		req.Header.Add("X-XSRF-TOKEN", "random id")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close() //nolint:errcheck // test
		return resp.StatusCode
	}

	t.Run("prov registered, native subject id", func(t *testing.T) {
		assert.Equal(t, http.StatusCreated, call(t, mint(t, "provider1", "a1b2c3d4-0000-4000-8000-000000000001")))
	})

	t.Run("prov unregistered, prefixed id", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, call(t, mint(t, "provider3", "provider1_id1")))
	})

	t.Run("no prov, registered prefix", func(t *testing.T) {
		assert.Equal(t, http.StatusCreated, call(t, mint(t, "", "provider1_id1")))
	})
}
