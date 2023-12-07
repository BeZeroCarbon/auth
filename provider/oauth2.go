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
	name            string
	infoURL         string
	endpoint        oauth2.Endpoint
	scopes          []string
	mapUser         func(UserData, []byte) token.User // map info from InfoURL to User
	bearerTokenHook BearerTokenHook                   // a way to get a Bearer token received from oauth2-provider
	conf            oauth2.Config

	jwksURL           string
	keyfunc           jwt.Keyfunc
	kfLock            *sync.Mutex
	refreshTokenStore RefreshTokenStore
	logoutURL         string
}

// RefreshTokenStore stores tokens, keyed by the claims user
type RefreshTokenStore interface {
	Save(token string, claims token.Claims) error
	Load(claims token.Claims) (string, error)
}

// Params to make initialized and ready to use provider
type Params struct {
	logger.L
	URL            string
	JwtService     TokenService
	Cid            string
	Csecret        string
	Issuer         string
	AvatarSaver    AvatarSaver
	UserAttributes UserAttributes

	UseOpenID bool // switch to OpenID flow, load user from an ID token instead of userinfo

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

// BearerTokenHook accepts provider name, user and token, received during oauth2 authentication
type BearerTokenHook func(provider string, user token.User, token oauth2.Token)

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
			Id:        cid,
			Audience:  aud,
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			NotBefore: time.Now().Add(-1 * time.Minute).Unix(),
		},
		NoAva:    r.URL.Query().Get("noava") == "1",
		Provider: p.Name(),
	}

	if _, err := p.JwtService.Set(w, claims); err != nil {
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
	oauthClaims, _, err := p.JwtService.Get(r)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to get token")
		return
	}

	if oauthClaims.Handshake == nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, nil, "invalid handshake token")
		return
	}

	retrievedState := oauthClaims.Handshake.State
	if retrievedState == "" || retrievedState != r.URL.Query().Get("state") {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, nil, "unexpected state")
		return
	}

	p.conf.RedirectURL = p.makeRedirURL(r.URL.Path)

	p.Logf("[DEBUG] token with state %s", retrievedState)
	tok, err := p.conf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "exchange failed")
		return
	}

	claims, err := p.loadUser(tok, oauthClaims)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to load user")
		return
	}

	client := p.conf.Client(context.Background(), tok)
	if claims.NoAva {
		claims.User.Picture = "" // reset picture on no avatar request
	}

	userWithAva, err := setAvatar(p.AvatarSaver, *claims.User, client)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
		return
	}
	claims.User = &userWithAva

	if _, err = p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	if p.bearerTokenHook != nil && tok != nil {
		p.Logf("[DEBUG] pass bearer token %s, %s", p.Name(), tok.TokenType)
		p.bearerTokenHook(p.Name(), *claims.User, *tok)
	}

	p.Logf("[DEBUG] user info %+v", claims.User)

	// redirect to back url if presented in login query params
	if oauthClaims.Handshake != nil && oauthClaims.Handshake.From != "" {
		http.Redirect(w, r, oauthClaims.Handshake.From, http.StatusTemporaryRedirect)
		return
	}
	rest.RenderJSON(w, &claims.User)
}

// LogoutHandler - GET /logout
func (p Oauth2Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
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

// Refresh returns the latest claims data from the source using the currently stored refresh token
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
