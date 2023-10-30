package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/auth/logger"
	"github.com/go-pkgz/auth/token"
)

// nolint
var (
	testConfirmedToken      = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJ0ZXN0MTIzOjpibGFoQHVzZXIuY29tIn19.D8AvAunK7Tj-P6P56VyaoZ-hyA6U8duZ9HV8-ACEya8`
	testConfirmedBadIDToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJibGFoQHVzZXIuY29tIn19.hB91-kyY9-Q2Ln6IJGR9StQi-QQiXYu8SV31YhOoTbc`
	testConfirmedGravatar   = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTg2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJncmF2YTo6ZWVmcmV0c291bEBnbWFpbC5jb20ifX0.yQTtG7neX3YjLZ-SGeiiNmwNfJWA7nR50KAxDw834XE`
	testConfirmedExpired    = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJyZW1hcms0MiIsImV4cCI6MTU2MDMwNzQxMiwibmJmIjoxNTYwMzA1NTUyLCJoYW5kc2hha2UiOnsiaWQiOiJ0ZXN0MTIzOjpibGFoQHVzZXIuY29tIn19.bCFMAwCg1_l4yuEzFYzd0q9PstY-auHe2rwLqltffqo`
)

func TestVerifyHandler_LoginSendConfirm(t *testing.T) {

	emailer := mockSender{}
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:   "iss-test",
		L:        logger.Std,
		Sender:   SenderFunc(emailer.Send),
		Template: "{{.User}} {{.Address}} {{.Site}} token:{{.Token}}",
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?address=blah@user.com&user=test123&site=remark42", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "blah@user.com", emailer.to)
	assert.Contains(t, emailer.text, "test123 blah@user.com remark42 token:")

	tknStr := strings.Split(emailer.text, " token:")[1]
	tkn, err := e.TokenService.Parse(tknStr)
	assert.NoError(t, err)
	t.Logf("%s %+v", tknStr, tkn)
	assert.Equal(t, "test123::blah@user.com", tkn.Handshake.ID)
	assert.Equal(t, "remark42", tkn.Audience)
	assert.True(t, tkn.ExpiresAt > tkn.NotBefore)

	assert.Equal(t, "test", e.Name())
}

func TestVerifyHandler_LoginSendConfirmRejected(t *testing.T) {

	emailer := mockSender{}
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:   "iss-test",
		L:        logger.Std,
		Sender:   SenderFunc(emailer.Send),
		Template: "{{.User}} {{.Address}} {{.Site}} token:{{.Token}}",
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	badUser := `<!DOCTYPE html> \n<html> \n<head>\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<title> Login Page </title>\n<style> \nBody {\n  font-family: Calibri, Helvetica, sans-serif;\n  background-color: pink;\n}\nbutton { \n       background-color: #4CAF50; \n       width: 100%;\n        color: orange; \n        padding: 15px; \n        margin: 10px 0px; \n        border: none; \n        cursor: pointer; \n         } \n form { \n        border: 3px solid #f1f1f1; \n    } \n input[type=text], input[type=password] { \n        width: 100%; \n        margin: 8px 0;\n        padding: 12px 20px; \n        display: inline-block; \n        border: 2px solid green; \n        box-sizing: border-box; \n    }\n button:hover { \n        opacity: 0.7; \n    } \n  .cancelbtn { \n        width: auto; \n        padding: 10px 18px;\n        margin: 10px 5px;\n    } \n      \n   \n .container { \n        padding: 25px; \n        background-color: lightblue;\n    } \n</style> \n</head>  \n<body>  \n    <center> <h1> Student Login Form </h1> </center> \n    <form>\n        <div class="container"> \n            <label>Username : </label> \n            <input type="text" placeholder="Enter Username" name="username" required>\n            <label>Password : </label> \n            <input type="password" placeholder="Enter Password" name="password" required>\n            <button type="submit">Login</button> \n            <input type="checkbox" checked="checked"> Remember me \n            <button type="button" class="cancelbtn"> Cancel</button> \n            Forgot <a href="#"> password? </a> \n        </div> \n    </form>   \n</body>   \n</html>\n\n \n`
	req, err := http.NewRequest("GET", "/login?address=blah@user.com&user="+url.QueryEscape(badUser)+"&site=remark42", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, "blah@user.com", emailer.to)
	// temporary: not doing a full check here to minimise conflicts with https://github.com/BeZeroCarbon/auth/pull/2
	assert.Contains(t, emailer.text, " blah@user.com remark42 token:")

	tknStr := strings.Split(emailer.text, " token:")[1]
	tkn, err := e.TokenService.Parse(tknStr)
	assert.NoError(t, err)
	t.Logf("%s %+v", tknStr, tkn)
	assert.Equal(t, badUser+"::blah@user.com", tkn.Handshake.ID)
	assert.Equal(t, "remark42", tkn.Audience)
	assert.True(t, tkn.ExpiresAt > tkn.NotBefore)

	assert.Equal(t, "test", e.Name())
}

func TestVerifyHandler_LoginAcceptConfirm(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedToken), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"test123","id":"test_63c1017838e567a526800790805eae4dc975402b","picture":""}`+"\n", rr.Body.String())

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	claims, err := e.TokenService.Parse(c.Value)
	require.NoError(t, err)
	t.Logf("%+v", claims)
	assert.Equal(t, "remark42", claims.Audience)
	assert.Equal(t, "iss-test", claims.Issuer)
	assert.True(t, claims.ExpiresAt > time.Now().Unix())
	assert.Equal(t, "test123", claims.User.Name)
	assert.Equal(t, true, claims.SessionOnly)
}

func TestVerifyHandler_LoginAcceptConfirmWithAvatar(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		UseGravatar:  true,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedGravatar), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"grava","id":"test_47dbf92d92954b1297cae73a864c159b4d847b9f","picture":"https://www.gravatar.com/avatar/c82739de14cf64affaf30856ca95b851"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginAcceptConfirmWithGrAvatarDisabled(t *testing.T) {
	e := VerifyHandler{
		ProviderName: "test",
		UseGravatar:  false,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(e.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", fmt.Sprintf("/login?token=%s&sess=1", testConfirmedGravatar), http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, `{"name":"grava","id":"test_47dbf92d92954b1297cae73a864c159b4d847b9f","picture":""}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginHandlerFailed(t *testing.T) {
	emailer := mockSender{}
	d := VerifyHandler{
		ProviderName: "test",
		Sender:       &emailer,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?user=myuser&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 400, rr.Code)
	assert.Equal(t, `{"error":"can't get user and address"}`+"\n", rr.Body.String())

	d.Sender = &mockSender{err: fmt.Errorf("some err")}
	handler = d.LoginHandler
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to send confirmation"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token=bad", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, `{"error":"failed to verify confirmation token"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token="+testConfirmedBadIDToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Equal(t, `{"error":"invalid handshake token"}`+"\n", rr.Body.String())

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?token="+testConfirmedExpired, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, `{"error":"failed to verify confirmation token"}`+"\n", rr.Body.String())

	d.Template = `{{.Blah}}`
	d.Sender = &mockSender{}
	handler = d.LoginHandler
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login?user=myuser&address=pppp&aud=xyz123", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Equal(t, `{"error":"can't execute confirmation template"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_LoginHandlerAvatarFailed(t *testing.T) {
	emailer := mockSender{}
	d := VerifyHandler{
		ProviderName: "test",
		Sender:       &emailer,
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer:      "iss-test",
		L:           logger.Std,
		AvatarSaver: mockAvatarSaverVerif{err: fmt.Errorf("avatar save error")},
	}

	handler := http.HandlerFunc(d.LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/login?token="+testConfirmedToken, http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 500, rr.Code)
	assert.Equal(t, `{"error":"failed to save avatar to proxy"}`+"\n", rr.Body.String())
}

func TestVerifyHandler_AuthHandler(t *testing.T) {
	d := VerifyHandler{}
	handler := http.HandlerFunc(d.AuthHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/callback", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
}

func TestVerifyHandler_Logout(t *testing.T) {
	d := VerifyHandler{
		ProviderName: "test",
		TokenService: token.NewService(token.Opts{
			SecretReader:   token.SecretFunc(func(string) (string, error) { return "secret", nil }),
			TokenDuration:  time.Hour,
			CookieDuration: time.Hour * 24 * 31,
		}),
		Issuer: "iss-test",
		L:      logger.Std,
	}

	handler := http.HandlerFunc(d.LogoutHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/logout", http.NoBody)
	require.NoError(t, err)
	handler.ServeHTTP(rr, req)
	assert.Equal(t, 200, rr.Code)
	assert.Equal(t, 2, len(rr.Header()["Set-Cookie"]))

	request := &http.Request{Header: http.Header{"Cookie": rr.Header()["Set-Cookie"]}}
	c, err := request.Cookie("JWT")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)

	c, err = request.Cookie("XSRF-TOKEN")
	require.NoError(t, err)
	assert.Equal(t, time.Time{}, c.Expires)
}

type mockSender struct {
	err error

	to   string
	text string
}

func (m *mockSender) Send(to, text string) error {
	if m.err != nil {
		return m.err
	}
	m.to = to
	m.text = text
	return nil
}

type mockAvatarSaverVerif struct {
	err error
	url string
}

func (a mockAvatarSaverVerif) Put(token.User, *http.Client) (avatarURL string, err error) {
	return a.url, a.err
}
