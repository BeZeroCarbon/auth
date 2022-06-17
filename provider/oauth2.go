package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/MicahParks/keyfunc"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-pkgz/rest"
	"github.com/golang-jwt/jwt"
	jwtv4 "github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

// Oauth2Handler implements /login, /callback and /logout handlers from aouth2 flow
type Oauth2Handler struct {
	Params

	// all of these fields specific to particular oauth2 provider
	name     string
	infoURL  string
	jwksURL  string
	endpoint oauth2.Endpoint
	scopes   []string
	mapUser  func(UserData, []byte) token.User // map info from InfoURL to User
	conf     oauth2.Config
	keyfunc  jwt.Keyfunc
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
	UseOpenID   bool // switch to OpenID flow instead of pure OAuth2, i.e. load userinfo from an ID token and do not use self-signed JWT tokens

	Port int // relevant for providers supporting port customization, for example dev oauth2
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
		kf, err := keyfunc.Get(service.jwksURL, keyfunc.Options{
			Client: http.DefaultClient,
			Ctx:    context.Background(),
			RefreshErrorHandler: func(err error) {
				p.Logf("[WARN] failed to refresh jwks: %s", err)
			},
			RefreshInterval:   1 * time.Hour,
			RefreshRateLimit:  1 * time.Minute,
			RefreshTimeout:    30 * time.Second,
			RefreshUnknownKID: true,
		})

		if err != nil {
			p.Logf("[ERROR] failed to init jwks: %s", err)
		}

		service.keyfunc = func(t *jwt.Token) (interface{}, error) {
			// only to pass kid across, to manage jwt v3 vs v4 compatibility
			v4token := jwtv4.Token{
				Header: map[string]interface{}{
					"kid": t.Header["kid"],
				},
			}

			return kf.Keyfunc(&v4token)
		}
	}

	p.Logf("[DEBUG] created %s oauth2, id=%s, redir=%s, endpoint=%s",
		service.name, service.Cid, service.makeRedirURLFromPath("/{route}/"+service.name+"/"), service.endpoint)
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
		NoAva: r.URL.Query().Get("noava") == "1",
	}

	if _, err := p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	// setting RedirectURL to rootURL/routingPath/provider/callback
	// e.g. http://localhost:8080/auth/github/callback
	p.conf.RedirectURL = p.makeRedirURL(r)

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

	p.conf.RedirectURL = p.makeRedirURL(r)

	p.Logf("[DEBUG] token with state %s", retrievedState)
	tok, err := p.conf.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "exchange failed")
		return
	}

	client := p.conf.Client(context.Background(), tok)

	var u token.User
	if p.UseOpenID {
		idToken, ok := tok.Extra("id_token").(string)
		if !ok || idToken == "" {
			rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, nil, "id_token is empty")
			return
		}

		claims := jwt.MapClaims{}
		parsedIDToken, err := jwt.ParseWithClaims(idToken, &claims, p.keyfunc)
		if err != nil {
			rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to parse id token")
			return
		}

		if !parsedIDToken.Valid {
			rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "invalid id token")
			return
		}

		u = p.mapUser(UserData(claims), []byte(idToken))
	}

	if !p.UseOpenID {
		uinfo, err := client.Get(p.infoURL)
		if err != nil {
			rest.SendErrorJSON(w, r, p.L, http.StatusServiceUnavailable, err, "failed to get client info")
			return
		}

		defer func() {
			if e := uinfo.Body.Close(); e != nil {
				p.Logf("[WARN] failed to close response body, %s", e)
			}
		}()

		data, err := io.ReadAll(uinfo.Body)
		if err != nil {
			rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to read user info")
			return
		}

		jData := map[string]interface{}{}
		if e := json.Unmarshal(data, &jData); e != nil {
			rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to unmarshal user info")
			return
		}
		p.Logf("[DEBUG] got raw user info %+v", jData)

		u = p.mapUser(jData, data)
	}

	if oauthClaims.NoAva {
		u.Picture = "" // reset picture on no avatar request
	}
	u, err = setAvatar(p.AvatarSaver, u, client)
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to save avatar to proxy")
		return
	}

	cid, err := randToken()
	if err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to make claim's id")
		return
	}
	claims := token.Claims{
		User: &u,
		StandardClaims: jwt.StandardClaims{
			Issuer:   p.Issuer,
			Id:       cid,
			Audience: oauthClaims.Audience,
		},
		SessionOnly: oauthClaims.SessionOnly,
		NoAva:       oauthClaims.NoAva,
	}

	if _, err = p.JwtService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusInternalServerError, err, "failed to set token")
		return
	}

	p.Logf("[DEBUG] user info %+v", u)

	// redirect to back url if presented in login query params
	if oauthClaims.Handshake != nil && oauthClaims.Handshake.From != "" {
		http.Redirect(w, r, oauthClaims.Handshake.From, http.StatusTemporaryRedirect)
		return
	}
	rest.RenderJSON(w, &u)
}

// LogoutHandler - GET /logout
func (p Oauth2Handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if _, _, err := p.JwtService.Get(r); err != nil {
		rest.SendErrorJSON(w, r, p.L, http.StatusForbidden, err, "logout not allowed")
		return
	}
	p.JwtService.Reset(w)
}

func (p Oauth2Handler) makeRedirURL(r *http.Request) string {
	host := p.URL
	if host == "" { // Base URL is not configured, use one from the request
		host = "http://" + r.Host
	}

	elems := strings.Split(r.URL.Path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimSuffix(host, "/") + strings.TrimSuffix(newPath, "/") + urlCallbackSuffix
}

func (p Oauth2Handler) makeRedirURLFromPath(path string) string {
	elems := strings.Split(path, "/")
	newPath := strings.Join(elems[:len(elems)-1], "/")

	return strings.TrimSuffix(p.URL, "/") + strings.TrimSuffix(newPath, "/") + urlCallbackSuffix
}
