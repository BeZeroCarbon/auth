// Package token wraps jwt-go library and provides higher level abstraction to work with JWT.
package token

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// Service wraps jwt operations
// supports both header and cookie tokens
type Service struct {
	Opts
}

// Claims stores user info for token and state & from from login
type Claims struct {
	jwt.StandardClaims
	User        *User      `json:"user,omitempty"` // user info
	SessionOnly bool       `json:"sess_only,omitempty"`
	Handshake   *Handshake `json:"handshake,omitempty"` // used for oauth handshake
	NoAva       bool       `json:"no-ava,omitempty"`    // disable avatar, always use identicon
	Provider    string     `json:"prov,omitempty"`      // which provider was used for login
}

// Handshake used for oauth handshake
type Handshake struct {
	State string `json:"state,omitempty"`
	From  string `json:"from,omitempty"`
	ID    string `json:"id,omitempty"`
}

const (
	// default names for cookies and headers
	defaultJWTCookieName   = "JWT"
	defaultJWTCookieDomain = ""
	defaultJWTHeaderKey    = "X-JWT"
	defaultXSRFCookieName  = "XSRF-TOKEN"
	defaultXSRFHeaderKey   = "X-XSRF-TOKEN"

	defaultIssuer = "go-pkgz/auth"

	defaultTokenDuration  = time.Minute * 15
	defaultCookieDuration = time.Hour * 24 * 31

	defaultTokenQuery = "token"

	// handshakeCookieSuffix is appended to JWTCookieName to derive the name of the dedicated OAuth
	// handshake cookie (e.g. "rp-token" -> "rp-token-oauth-state"). Deriving it keeps the name out of
	// Opts: there is nothing to tune, and a config knob would need plumbing through every consumer
	// for no benefit.
	handshakeCookieSuffix = "-oauth-state"
)

// handshakeDuration is the lifetime of an OAuth handshake: both the exp claim on the handshake
// token and the MaxAge of the cookie carrying it. SetHandshake stamps both from it, so there is one
// place that decides how long a login may take.
//
// It is an hour rather than the 30 minutes LoginHandler used to set because that value was never
// enforced: AuthHandler read the handshake through Get, which skips the expiry check for
// cookie-sourced tokens, so a callback arriving long after login still completed. GetHandshake does
// enforce it (a signed handshake would otherwise be replayable indefinitely), which makes the TTL
// user-visible for the first time: it has to outlast whatever the user does on the identity
// provider's hosted UI (MFA enrolment, a forced password change, a password reset) before the
// callback comes back.
const handshakeDuration = time.Hour

// Errors returned by GetHandshake. They are sentinels so the OAuth callback can map a rejection to a
// response without string matching; all of them are expected, public-endpoint denials.
//
// The split between ErrNoHandshake and the other three is what tells the callback whether it may
// clear the handshake cookie: only a candidate that was examined and condemned justifies that.
// ErrNoHandshake means nothing was examined at all, and a request that presented no candidate must
// never be able to destroy a login in flight, because /callback is public and unauthenticated.
var (
	// ErrNoHandshake means no candidate was even examined: the callback carried no state, or neither
	// cookie was presented
	ErrNoHandshake = fmt.Errorf("no handshake token")
	// ErrHandshakeInvalid means a cookie was presented but held nothing usable: it did not parse, its
	// signature was rejected, or it is a token of another kind (a user session)
	ErrHandshakeInvalid = fmt.Errorf("invalid handshake token")
	// ErrHandshakeExpired means a handshake token was found but has expired
	ErrHandshakeExpired = fmt.Errorf("handshake expired")
	// ErrHandshakeStateMismatch means a live handshake token was found but its state does not match
	ErrHandshakeStateMismatch = fmt.Errorf("handshake state mismatch")
)

// Opts holds constructor params
type Opts struct {
	SecretReader   Secret
	ClaimsUpd      ClaimsUpdater
	SecureCookies  bool
	TokenDuration  time.Duration
	CookieDuration time.Duration
	DisableXSRF    bool
	DisableIAT     bool // disable IssuedAt claim
	// optional (custom) names for cookies and headers
	JWTCookieName   string
	JWTCookieDomain string
	JWTHeaderKey    string
	XSRFCookieName  string
	XSRFHeaderKey   string
	JWTQuery        string
	AudienceReader  Audience      // allowed aud values
	Issuer          string        // optional value for iss claim, usually application name
	AudSecrets      bool          // uses different secret for differed auds. important: adds pre-parsing of unverified token
	SendJWTHeader   bool          // if enabled send JWT as a header instead of cookie
	SameSite        http.SameSite // define a cookie attribute making it impossible for the browser to send this cookie cross-site
}

// NewService makes JWT service
func NewService(opts Opts) *Service {
	res := Service{Opts: opts}

	setDefault := func(fld *string, def string) {
		if *fld == "" {
			*fld = def
		}
	}

	setDefault(&res.JWTCookieName, defaultJWTCookieName)
	setDefault(&res.JWTHeaderKey, defaultJWTHeaderKey)
	setDefault(&res.XSRFCookieName, defaultXSRFCookieName)
	setDefault(&res.XSRFHeaderKey, defaultXSRFHeaderKey)
	setDefault(&res.JWTQuery, defaultTokenQuery)
	setDefault(&res.Issuer, defaultIssuer)
	setDefault(&res.JWTCookieDomain, defaultJWTCookieDomain)

	if opts.TokenDuration == 0 {
		res.TokenDuration = defaultTokenDuration
	}

	if opts.CookieDuration == 0 {
		res.CookieDuration = defaultCookieDuration
	}

	return &res
}

// Token makes token with claims
func (j *Service) Token(claims Claims) (string, error) {

	// make token for allowed aud values only, rejects others

	// update claims with ClaimsUpdFunc defined by consumer
	if j.ClaimsUpd != nil {
		claims = j.ClaimsUpd.Update(claims)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	if j.SecretReader == nil {
		return "", fmt.Errorf("secret reader not defined")
	}

	if err := j.checkAuds(&claims, j.AudienceReader); err != nil {
		return "", fmt.Errorf("aud rejected: %w", err)
	}

	secret, err := j.SecretReader.Get(claims.Audience) // get secret via consumer defined SecretReader
	if err != nil {
		return "", fmt.Errorf("can't get secret: %w", err)
	}

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("can't sign token: %w", err)
	}
	return tokenString, nil
}

// Parse token string and verify. Not checking for expiration
func (j *Service) Parse(tokenString string) (Claims, error) {
	parser := jwt.Parser{SkipClaimsValidation: true} // allow parsing of expired tokens

	if j.SecretReader == nil {
		return Claims{}, fmt.Errorf("secret reader not defined")
	}

	aud := "ignore"
	if j.AudSecrets {
		var err error
		aud, err = j.aud(tokenString)
		if err != nil {
			return Claims{}, fmt.Errorf("can't retrieve audience from the token")
		}
	}

	secret, err := j.SecretReader.Get(aud)
	if err != nil {
		return Claims{}, fmt.Errorf("can't get secret: %w", err)
	}

	token, err := parser.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return Claims{}, fmt.Errorf("can't parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return Claims{}, fmt.Errorf("invalid token")
	}

	if err = j.checkAuds(claims, j.AudienceReader); err != nil {
		return Claims{}, fmt.Errorf("aud rejected: %w", err)
	}
	return *claims, j.validate(claims)
}

// aud pre-parse token and extracts aud from the claim
// important! this step ignores token verification, should not be used for any validations
func (j *Service) aud(tokenString string) (string, error) {
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return "", fmt.Errorf("can't pre-parse token: %w", err)
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", fmt.Errorf("invalid token")
	}
	if strings.TrimSpace(claims.Audience) == "" {
		return "", fmt.Errorf("empty aud")
	}
	return claims.Audience, nil
}

func (j *Service) validate(claims *Claims) error {
	cerr := claims.Valid()

	if cerr == nil {
		return nil
	}

	if e, ok := cerr.(*jwt.ValidationError); ok {
		if e.Errors == jwt.ValidationErrorExpired {
			return nil // allow expired tokens
		}
	}

	return cerr
}

// Set creates token cookie with xsrf cookie and put it to ResponseWriter
// accepts claims and sets expiration if none defined. permanent flag means long-living cookie,
// false makes it session only.
func (j *Service) Set(w http.ResponseWriter, claims Claims) (Claims, error) {
	claims = j.withDefaults(claims, j.TokenDuration)

	tokenString, err := j.Token(claims)
	if err != nil {
		return Claims{}, fmt.Errorf("failed to make token token: %w", err)
	}

	j.writeSession(w, tokenString, claims)
	return claims, nil
}

// withDefaults fills in the claim fields the setters default when the caller left them unset.
// Split out of Set so SetHandshake applies exactly the same rules with its own duration.
func (j *Service) withDefaults(claims Claims, duration time.Duration) Claims {
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(duration).Unix()
	}

	if claims.Issuer == "" {
		claims.Issuer = j.Issuer
	}

	if !j.DisableIAT {
		claims.IssuedAt = time.Now().Unix()
	}

	return claims
}

// writeSession sends an already-signed token to the client as the session cookie pair, or as the
// JWT header when SendJWTHeader is set. Split out of Set so the handshake dual-write can reuse it
// with the very same token string instead of re-signing the claims.
func (j *Service) writeSession(w http.ResponseWriter, tokenString string, claims Claims) {
	if j.SendJWTHeader {
		w.Header().Set(j.JWTHeaderKey, tokenString)
		return
	}

	cookieExpiration := 0 // session cookie
	if !claims.SessionOnly && claims.Handshake == nil {
		cookieExpiration = int(j.CookieDuration.Seconds())
	}

	// note: HttpOnly is deliberately true here and false in Reset. That asymmetry comes from
	// upstream; it looks like a bug but "fixing" it changes emitted headers, so it is pinned by test.
	jwtCookie := http.Cookie{Name: j.JWTCookieName, Value: tokenString, HttpOnly: true, Path: "/", Domain: j.JWTCookieDomain,
		MaxAge: cookieExpiration, Secure: j.SecureCookies, SameSite: j.SameSite}
	http.SetCookie(w, &jwtCookie)

	xsrfCookie := http.Cookie{Name: j.XSRFCookieName, Value: claims.Id, HttpOnly: false, Path: "/", Domain: j.JWTCookieDomain,
		MaxAge: cookieExpiration, Secure: j.SecureCookies, SameSite: j.SameSite}
	http.SetCookie(w, &xsrfCookie)
}

// Get token from url, header or cookie
// if cookie used, verify xsrf token to match
func (j *Service) Get(r *http.Request) (Claims, string, error) {

	fromCookie := false
	tokenString := ""

	// try to get from "token" query param
	if tkQuery := r.URL.Query().Get(j.JWTQuery); tkQuery != "" {
		tokenString = tkQuery
	}

	// try to get from JWT header
	if tokenHeader := r.Header.Get(j.JWTHeaderKey); tokenHeader != "" && tokenString == "" {
		tokenString = tokenHeader
	}

	// try to get from JWT cookie
	if tokenString == "" {
		fromCookie = true
		jc, err := r.Cookie(j.JWTCookieName)
		if err != nil {
			return Claims{}, "", fmt.Errorf("token cookie was not presented: %w", err)
		}
		tokenString = jc.Value
	}

	claims, err := j.Parse(tokenString)
	if err != nil {
		return Claims{}, "", fmt.Errorf("failed to get token: %w", err)
	}

	// promote claim's aud to User.Audience
	if claims.User != nil {
		claims.User.Audience = claims.Audience
	}

	if !fromCookie && j.IsExpired(claims) {
		return Claims{}, "", fmt.Errorf("token expired")
	}

	if j.DisableXSRF {
		return claims, tokenString, nil
	}

	if fromCookie && claims.User != nil {
		xsrf := r.Header.Get(j.XSRFHeaderKey)
		if claims.Id != xsrf {
			return Claims{}, "", fmt.Errorf("xsrf mismatch")
		}
	}

	return claims, tokenString, nil
}

// IsExpired returns true if claims expired
func (j *Service) IsExpired(claims Claims) bool {
	return !claims.VerifyExpiresAt(time.Now().Unix(), true)
}

// Reset token's cookies
func (j *Service) Reset(w http.ResponseWriter) {
	jwtCookie := http.Cookie{Name: j.JWTCookieName, Value: "", HttpOnly: false, Path: "/", Domain: j.JWTCookieDomain,
		MaxAge: -1, Expires: time.Unix(0, 0), Secure: j.SecureCookies, SameSite: j.SameSite}
	http.SetCookie(w, &jwtCookie)

	xsrfCookie := http.Cookie{Name: j.XSRFCookieName, Value: "", HttpOnly: false, Path: "/", Domain: j.JWTCookieDomain,
		MaxAge: -1, Expires: time.Unix(0, 0), Secure: j.SecureCookies, SameSite: j.SameSite}
	http.SetCookie(w, &xsrfCookie)
}

// handshakeCookieName returns the name of the dedicated OAuth handshake cookie. It is derived from
// JWTCookieName rather than configured, see handshakeCookieSuffix.
func (j *Service) handshakeCookieName() string {
	return j.JWTCookieName + handshakeCookieSuffix
}

// SetHandshake writes the OAuth handshake token to its own dedicated cookie and, for stage 1 of the
// rollout only, mirrors it into the session cookie exactly as LoginHandler used to via Set.
//
// The dedicated cookie exists so a concurrent request refreshing (Set) or clearing (Reset) the
// session cookie can no longer destroy an in-flight login handshake. Neither Set nor Reset ever
// touch it; only SetHandshake and ResetHandshake do.
//
// Both cookies carry the same token: it is minted once here rather than by a Set call followed by a
// SetHandshake call, so ClaimsUpd fires once per login, and so a signing failure cannot leave the
// session cookie replaced while the handshake cookie is missing.
//
// SameSite on the dedicated cookie is Lax, a deliberate divergence from the session cookie's
// configurable SameSite: the callback arrives as a cross-site top-level redirect from the identity
// provider, and a Strict cookie would not be sent with it.
//
// TODO(stage 2): drop the writeSession call below once every consumer has run this version for a
// full CookieDuration, leaving only the dedicated cookie.
func (j *Service) SetHandshake(w http.ResponseWriter, claims Claims) error {
	if claims.Handshake == nil {
		return fmt.Errorf("not a handshake token")
	}

	// stamped, not defaulted: the handshake's lifetime is not the caller's to choose. withDefaults
	// only fills exp in when it is unset, so a caller presetting a longer one would get a token
	// outliving the cookie carrying it, and GetHandshake trusts exp, not the cookie's MaxAge, so
	// that token would stay redeemable by anyone who kept a copy. exp is therefore already set by the
	// time withDefaults runs, which is why it is passed no duration: it only fills in iss and iat here.
	claims.ExpiresAt = time.Now().Add(handshakeDuration).Unix()
	claims = j.withDefaults(claims, 0)

	tokenString, err := j.Token(claims)
	if err != nil {
		return fmt.Errorf("failed to make handshake token: %w", err)
	}

	// session cookies first, so the Set-Cookie order a login emits is unchanged
	j.writeSession(w, tokenString, claims)

	http.SetCookie(w, &http.Cookie{Name: j.handshakeCookieName(), Value: tokenString, HttpOnly: true,
		Path: "/", Domain: j.JWTCookieDomain, MaxAge: int(handshakeDuration.Seconds()),
		Secure: j.SecureCookies, SameSite: http.SameSiteLaxMode})

	return nil
}

// GetHandshake returns the handshake claims matching the given oauth2 state.
//
// It reads both the dedicated handshake cookie and the session cookie, because during the staged
// rollout the login handler dual-writes the handshake to both: a login served by a new instance may
// have its callback served by an old one, and vice versa. Selection is by state match, never by
// "first cookie present", otherwise a stale handshake left in the dedicated cookie by an abandoned
// login would mask a valid one in the session cookie.
//
// TODO(stage 2): read only handshakeCookieName() once the rollout has drained.
//
// Expiry is enforced here, before state selection: Parse deliberately tolerates expired tokens (see
// validate) and a cookie MaxAge is only a client-side hint, so without this check a retained or
// replayed signed handshake would stay usable forever.
//
// Unlike Get, no XSRF header is ever demanded: the callback is a top-level redirect back from the
// identity provider and cannot carry one.
//
// Every rejection is reported with the sentinel that says what happened to each candidate, joined
// across the two cookies so errors.Is matches any of them. ErrNoHandshake specifically means
// "nothing was examined", which is what stops a callback carrying no state, or no cookies at all,
// from clearing a live handshake.
func (j *Service) GetHandshake(r *http.Request, state string) (Claims, error) {
	if state == "" {
		return Claims{}, fmt.Errorf("%w: empty state", ErrNoHandshake)
	}

	var errs handshakeErrors
	for _, name := range []string{j.handshakeCookieName(), j.JWTCookieName} {
		c, err := r.Cookie(name)
		if err != nil || c.Value == "" {
			errs = append(errs, fmt.Errorf("%w: %s cookie was not presented", ErrNoHandshake, name))
			continue
		}

		claims, err := j.Parse(c.Value)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %s: %v", ErrHandshakeInvalid, name, err))
			continue
		}

		if claims.Handshake == nil || claims.Handshake.State == "" {
			errs = append(errs, fmt.Errorf("%w: %s does not hold a handshake", ErrHandshakeInvalid, name))
			continue
		}

		if j.IsExpired(claims) {
			errs = append(errs, fmt.Errorf("%w: %s", ErrHandshakeExpired, name))
			continue
		}

		if claims.Handshake.State != state {
			errs = append(errs, fmt.Errorf("%w: %s", ErrHandshakeStateMismatch, name))
			continue
		}

		return claims, nil
	}

	return Claims{}, errs
}

// handshakeErrors is the per-candidate verdict list GetHandshake returns. It is a hand-rolled join
// rather than errors.Join because this module still declares go 1.17; errors.Is reaches every
// member through Is, and Unwrap exposes them to callers on newer toolchains.
type handshakeErrors []error

func (e handshakeErrors) Error() string {
	msgs := make([]string, 0, len(e))
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// Is reports whether any of the joined verdicts matches target
func (e handshakeErrors) Is(target error) bool {
	for _, err := range e {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// Unwrap returns the joined verdicts, the multi-error convention Go 1.20+ understands
func (e handshakeErrors) Unwrap() []error { return e }

// ResetHandshake clears the dedicated OAuth handshake cookie.
//
// Kept separate from Reset on purpose: Reset is not logout-specific, the auth middleware also calls
// it on validator rejection and on refresh failure. Folding the handshake into Reset would let a
// concurrent failing request delete an in-flight login, the same cross-request coupling this
// cookie exists to remove.
func (j *Service) ResetHandshake(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: j.handshakeCookieName(), Value: "", HttpOnly: true, Path: "/",
		Domain: j.JWTCookieDomain, MaxAge: -1, Expires: time.Unix(0, 0), Secure: j.SecureCookies,
		SameSite: http.SameSiteLaxMode})
}

// checkAuds verifies if claims.Audience in the list of allowed by audReader
func (j *Service) checkAuds(claims *Claims, audReader Audience) error {
	if audReader == nil { // lack of any allowed means any
		return nil
	}
	auds, err := audReader.Get()
	if err != nil {
		return fmt.Errorf("failed to get auds: %w", err)
	}
	for _, a := range auds {
		if strings.EqualFold(a, claims.Audience) {
			return nil
		}
	}
	return fmt.Errorf("aud %q not allowed", claims.Audience)
}

func (c Claims) String() string {
	b, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("%+v %+v", c.StandardClaims, c.User)
	}
	return string(b)
}

// Secret defines interface returning secret key for given id (aud)
type Secret interface {
	Get(aud string) (string, error) // aud matching is optional. Implementation may decide if supported or ignored
}

// SecretFunc type is an adapter to allow the use of ordinary functions as Secret. If f is a function
// with the appropriate signature, SecretFunc(f) is a Handler that calls f.
type SecretFunc func(aud string) (string, error)

// Get calls f()
func (f SecretFunc) Get(aud string) (string, error) {
	return f(aud)
}

// ClaimsUpdater defines interface adding extras to claims
type ClaimsUpdater interface {
	Update(claims Claims) Claims
}

// ClaimsUpdFunc type is an adapter to allow the use of ordinary functions as ClaimsUpdater. If f is a function
// with the appropriate signature, ClaimsUpdFunc(f) is a Handler that calls f.
type ClaimsUpdFunc func(claims Claims) Claims

// Update calls f(id)
func (f ClaimsUpdFunc) Update(claims Claims) Claims {
	return f(claims)
}

// Validator defines interface to accept o reject claims with consumer defined logic
// It works with valid token and allows to reject some, based on token match or user's fields
type Validator interface {
	Validate(token string, claims Claims) bool
}

// ValidatorFunc type is an adapter to allow the use of ordinary functions as Validator. If f is a function
// with the appropriate signature, ValidatorFunc(f) is a Validator that calls f.
type ValidatorFunc func(token string, claims Claims) bool

// Validate calls f(id)
func (f ValidatorFunc) Validate(token string, claims Claims) bool {
	return f(token, claims)
}

// Audience defines interface returning list of allowed audiences
type Audience interface {
	Get() ([]string, error)
}

// AudienceFunc type is an adapter to allow the use of ordinary functions as Audience.
type AudienceFunc func() ([]string, error)

// Get calls f()
func (f AudienceFunc) Get() ([]string, error) {
	return f()
}
