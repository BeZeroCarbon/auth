package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-pkgz/rest"
	"github.com/golang-jwt/jwt"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

const clockSkew = 10 * time.Second

// Oauth2Handler implements /login, /callback and /logout handlers from aouth2 flow
type Oauth2Handler struct {
	Params

	// all of these fields specific to particular oauth2 provider
	name              string
	infoURL           string
	jwksURL           string
	endpoint          oauth2.Endpoint
	scopes            []string
	mapUser           func(UserData, []byte) token.User // map info from InfoURL to User
	conf              oauth2.Config
	keyfunc           jwt.Keyfunc
	kfLock            *sync.Mutex
	refreshTokenStore RefreshTokenStore
	logoutURL         string
}

type RefreshTokenStore interface {
	Save(token string, claims token.Claims) error
	Load(claims token.Claims) (string, error)
}

// Params to make initialized and ready to use provider
type Params struct {
	logger.L
	URL         string
	JwtService  TokenService
	Cid         string
	Csecret     string
	Issuer      string
	AvatarSaver AvatarSaver
	UseOpenID   bool // switch to OpenID flow, load user from an ID token instead of userinfo

	Port int    // relevant for providers supporting port customization, for example dev oauth2
	Host string // relevant for providers supporting host customization, for example dev oauth2
}

// UserData is type for user information returned from oauth2 providers /info API method
type UserData map[string]interface{}

// Value returns value for key or empty string if not found
func (u UserData) Value(key string) string {
	// json.Unmarshal converts json "null" value to go's "nil", in this case return empty string
	if val, ok := u[key]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// initOauth2Handler makes oauth2 handler for given provider
func initOauth2Handler(p Params, service Oauth2Handler) Oauth2Handler {
	if p.L == nil {
		p.L = logger.NoOp
	}
	p.Logf("[INFO] init oauth2 service %s", service.name)
	service.Params = p
	service.conf = oauth2.Config{
		ClientID:     service.Cid,
		ClientSecret: service.Csecret,
		Scopes:       service.scopes,
		Endpoint:     service.endpoint,
	}

	if p.UseOpenID {
		service.kfLock = &sync.Mutex{}
		err := service.tryInitJWKSKeyfunc()
		if err != nil {
			p.Logf("[ERROR] failed to load JWT keys to enable OpenID, will retry on token request: %s", err)
		}
	}

	p.Logf("[DEBUG] created %s oauth2, id=%s, redir=%s, endpoint=%s",
		service.name, service.Cid, service.makeRedirURL("/{route}/"+service.name+"/"), service.endpoint)
	return service
}

// Name returns provider name
func (p Oauth2Handler) Name() string { return p.name }

// LoginHandler - GET /login?from=redirect-back-url&[site|aud]=siteID&session=1&noava=1
func (p Oauth2Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {

	p.Logf("[DEBUG] login with %s", p.Name())
	// make state (random) and store in session
	state, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to make oauth2 state")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}

	aud := r.URL.Query().Get("site") // legacy, for back compat
	if aud == "" {
		aud = r.URL.Query().Get("aud")
	}

	claims := token.Claims{
		Handshake: &token.Handshake{
			State: state,
			From:  r.URL.Query().Get("from"),
		},
		SessionOnly: r.URL.Query().Get("session") != "" && r.URL.Query().Get("session") != "0",
		StandardClaims: jwt.StandardClaims{
			// no ExpiresAt: SetHandshake stamps it, so the handshake's lifetime is decided in one place
			Id:        cid,
			Audience:  aud,
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
		},
		NoAva:    r.URL.Query().Get("noava") == "1",
		Provider: p.Name(),
	}

	// SetHandshake writes the handshake to its own cookie, where a concurrent session refresh can't
	// clobber it, and (stage 1 of the rollout) mirrors it into the session cookie as Set used to, so
	// a login served by a new instance can still have its callback served by an old one during a
	// rolling deploy. Both cookies get the same, once-minted token; see token.Service.SetHandshake
	// for the TODO(stage 2) that drops the session-cookie half.
	if err = p.JwtService.SetHandshake(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// setting RedirectURL to rootURL/routingPath/provider/callback
	// e.g. http://localhost:8080/auth/github/callback
	p.conf.RedirectURL = p.makeRedirURL(r.URL.Path)

	// return login url
	loginURL := p.conf.AuthCodeURL(state)
	p.Logf("[DEBUG] login url %s, claims=%+v", loginURL, claims)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// AuthHandler fills user info and redirects to "from" url. This is callback url redirected locally by browser
// GET /callback
func (p Oauth2Handler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	// Dual-read: GetHandshake checks both the dedicated handshake cookie and the session cookie and
	// picks whichever holds a live handshake matching the state we were called back with. It never
	// demands an XSRF header, which a top-level redirect back from the provider cannot carry. Every
	// exit that consumed or condemned a handshake clears the cookie; the logout handler never runs
	// during a callback, so this is the only place that can retire one.
	oauthClaims, err := p.JwtService.GetHandshake(r, r.URL.Query().Get("state"))
	if err != nil {
		// All of these are expected denials on a public endpoint: stale tabs, abandoned logins and
		// hostile probes land here routinely, hence 403 rather than 500.
		//
		// Clearing the cookie is the dangerous half of this switch, so only a candidate that was
		// actually examined and condemned earns it. Anything else would let an unauthenticated
		// cross-site request destroy a login in flight.
		//
		// The arm order is load-bearing: GetHandshake joins the verdicts of both candidates, so
		// several sentinels can be present at once (a logged-in user with a live handshake in the
		// dedicated cookie and an ordinary session token in the session cookie yields
		// StateMismatch+Invalid). Arms are therefore ordered least-destructive first, so the
		// don't-clear verdict wins over a clear verdict on the other cookie.
		switch {
		case errors.Is(err, token.ErrHandshakeStateMismatch):
			// deliberately NOT cleared: the cookie is a single slot, and a live handshake that
			// doesn't match this callback belongs to another login the user has in flight (two tabs,
			// a double-click). Clearing here would kill that one. It retires itself via exp/MaxAge.
			rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, err, "unexpected state")
		case errors.Is(err, token.ErrHandshakeExpired):
			p.JwtService.ResetHandshake(w)
			rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, err, "expired handshake token")
		case errors.Is(err, token.ErrHandshakeInvalid):
			// a cookie was presented and holds nothing usable (unparsable, tampered, or a session
			// token that clobbered the handshake): dead weight, safe to bin
			p.JwtService.ResetHandshake(w)
			rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, err, "invalid handshake token")
		default:
			// token.ErrNoHandshake: no candidate was examined, either no state on the request or no
			// cookie presented. Neither says the browser has nothing to lose. GetHandshake
			// short-circuits on an empty state before it reads any cookie, so a bare GET /callback,
			// which anyone can make a victim's browser issue as a top-level navigation and which does
			// carry the SameSite=Lax handshake cookie, lands here while a login is in flight; clearing
			// would kill it. A request that presented no cookie tells us just as little: it may simply
			// not have been sent. So this arm must not clear.
			rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, err, "no handshake token")
		}
		return
	}

	// a handshake minted at another provider's /login must not be redeemable here. The code exchange
	// would fail anyway against a different client_id, but that surfaces as a confusing 500 and this
	// is the CSRF boundary. Empty is tolerated: nothing but LoginHandler mints handshakes, and it has
	// always set the claim, but a hand-rolled fixture may not.
	//
	// Not cleared, for the same reason a state mismatch is not: the handshake is live and it is the
	// user's, it just belongs to a login started at another provider, which may still complete at its
	// own callback. Only its exp retires it.
	if oauthClaims.Provider != "" && oauthClaims.Provider != p.Name() {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden,
			fmt.Errorf("handshake issued for provider %q", oauthClaims.Provider), "unexpected provider")
		return
	}

	p.conf.RedirectURL = p.makeRedirURL(r.URL.Path)

	p.Logf("[DEBUG] token with state %s", oauthClaims.Handshake.State)
	tok, err := p.conf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		p.JwtService.ResetHandshake(w)
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "exchange failed")
		return
	}

	claims, err := p.loadUser(tok, oauthClaims)
	if err != nil {
		p.JwtService.ResetHandshake(w)
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to load user")
		return
	}

	client := p.conf.Client(context.Background(), tok)
	if claims.NoAva {
		claims.User.Picture = "" // reset picture on no avatar request
	}

	userWithAva, err := setAvatar(p.AvatarSaver, *claims.User, client)
	claims.User = &userWithAva

	if _, err = p.JwtService.Set(w, claims); err != nil {
		p.JwtService.ResetHandshake(w)
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// handshake consumed, retire its cookie. Written after Set so the session cookies keep their
	// position in the response, which the existing tests assert on by index.
	p.JwtService.ResetHandshake(w)

	p.Logf("[DEBUG] user info %+v", claims.User)

	// redirect to back url if presented in login query params. GetHandshake only ever returns claims
	// with a non-nil Handshake
	if oauthClaims.Handshake.From != "" {
		http.Redirect(w, r, oauthClaims.Handshake.From, http.StatusTemporaryRedirect)
		return
	}
	rest.RenderJSON(w, &claims.User)
}

// LogoutHandler - GET /logout
func (p Oauth2Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// unconditionally, and before the Get check below: that check returns early with 403 whenever the
	// session cookie is missing or unreadable, which is exactly when a user is trying to log out of a
	// broken session and we would otherwise strand the handshake cookie in their browser.
	p.JwtService.ResetHandshake(w)

	if _, _, err := p.JwtService.Get(r); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, err, "logout not allowed")
		return
	}
	p.JwtService.Reset(w)
	if p.logoutURL == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if p.logoutURL != "" {
		// can't return redirect because logout is called via XHR request to pass XSRF and will be blocked by CORS
		// client should redirect to logoutURL manually
		rest.RenderJSON(w, map[string]string{"logout_url": p.logoutURL})
		return
	}
}

func (p Oauth2Handler) Refresh(claims token.Claims) (token.Claims, error) {
	if p.refreshTokenStore == nil {
		p.L.Logf("[WARN] refresh token store is not set, can't refresh tokens")
		return claims, nil
	}

	rTk, err := p.refreshTokenStore.Load(claims)
	if err != nil {
		return token.Claims{}, err
	}

	tokenSource := p.conf.TokenSource(context.Background(), &oauth2.Token{RefreshToken: rTk})
	tok, err := tokenSource.Token()
	if err != nil {
		return token.Claims{}, err
	}

	return p.loadUser(tok, claims)
}

func (p Oauth2Handler) loadUser(tok *oauth2.Token, claims token.Claims) (token.Claims, error) {
	var err error
	var u token.User
	var userData UserData
	var rawUserData []byte

	if p.UseOpenID {
		userData, rawUserData, err = p.loadUserFromIDToken(tok)
	}

	if !p.UseOpenID {
		client := p.conf.Client(context.Background(), tok)
		userData, rawUserData, err = p.loadUserFromEndpoint(client)
	}

	if err != nil {
		return token.Claims{}, err
	}

	u = p.mapUser(userData, rawUserData)

	cid, err := randToken()
	if err != nil {
		return token.Claims{}, err
	}

	tk := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Issuer:   p.Issuer,
			Id:       cid,
			Audience: claims.Audience,
		},
		SessionOnly: claims.SessionOnly,
		NoAva:       claims.NoAva,
		Provider:    p.Name(),
	}

	if p.refreshTokenStore != nil {
		err = p.refreshTokenStore.Save(tok.RefreshToken, tk)
		if err != nil {
			return token.Claims{}, errors.Wrap(err, "failed to save refresh token")
		}
	}

	return tk, nil
}

func (p Oauth2Handler) loadUserFromIDToken(tok *oauth2.Token) (UserData, []byte, error) {
	idToken, ok := tok.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, nil, fmt.Errorf("id_token not found")
	}

	if p.keyfunc == nil {
		err := p.tryInitJWKSKeyfunc()
		if err != nil {
			return nil, nil, errors.Wrap(err, "can't load JWKS keys")
		}
	}

	claims := jwt.MapClaims{}
	parser := jwt.Parser{
		// claims validation is not considering clock skew and randomly failing with iat validation
		// nbf and exp are validated below
		SkipClaimsValidation: true,
	}

	parsedIDToken, err := parser.ParseWithClaims(idToken, &claims, p.keyfunc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse id token")
	}

	if !parsedIDToken.Valid {
		return nil, nil, fmt.Errorf("invalid id token")
	}

	now := time.Now().Add(clockSkew).Unix()
	if !claims.VerifyExpiresAt(now, false) {
		return nil, nil, fmt.Errorf("id token expired")
	}

	if !claims.VerifyNotBefore(now, false) {
		return nil, nil, fmt.Errorf("id token is not yet valid")
	}

	return UserData(claims), []byte(idToken), nil
}

func (p Oauth2Handler) loadUserFromEndpoint(client *http.Client) (UserData, []byte, error) {
	uinfo, err := client.Get(p.infoURL)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get client info")
	}

	defer func() {
		if e := uinfo.Body.Close(); e != nil {
			p.Logf("[WARN] failed to close response body, %s", e)
		}
	}()

	data, err := io.ReadAll(uinfo.Body)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to read user info")
	}

	jData := map[string]interface{}{}
	if e := json.Unmarshal(data, &jData); e != nil {
		return nil, nil, errors.Wrap(e, "failed to unmarshal user info")
	}
	p.Logf("[DEBUG] got raw user info %+v", jData)

	return jData, data, nil
}

func (p Oauth2Handler) makeRedirURL(path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimSuffix(p.URL, "/") + strings.TrimSuffix(newPath, "/") + urlCallbackSuffix
}

func (p *Oauth2Handler) tryInitJWKSKeyfunc() error {
	p.kfLock.Lock()
	defer p.kfLock.Unlock()
	if p.keyfunc != nil {
		return nil
	}

	kf, err := keyfunc.Get(p.jwksURL, keyfunc.Options{
		Client:            http.DefaultClient,
		Ctx:               context.Background(),
		RefreshUnknownKID: true,            // to support key rotation, re-load keys if KID is unknown
		RefreshRateLimit:  1 * time.Minute, // but no often than once per minute
	})

	if err != nil {
		return err
	}

	p.keyfunc = func(t *jwt.Token) (interface{}, error) {
		// only to pass kid across, to manage jwt v3 vs v4 compatibility
		v4token := jwtv4.Token{
			Header: map[string]interface{}{
				"kid": t.Header["kid"],
			},
		}

		return kf.Keyfunc(&v4token)
	}

	return nil
}
