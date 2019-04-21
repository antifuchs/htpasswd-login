package htpasswd_test

import (
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"strings"

	htpasswd "github.com/antifuchs/htpasswd-login"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type timer struct {
	at time.Time
}

func (t *timer) now() time.Time {
	return t.at
}

var _ htpasswd.Timesource = (&timer{}).now

func service(t *testing.T, ti *timer) (*htpasswd.Service, string, *httptest.Server) {
	dir, err := ioutil.TempDir("/tmp", "htpasswd-test")
	if err != nil {
		t.Fatal(err)
	}
	srv := &htpasswd.Service{
		Now:            ti.now,
		SessionDir:     dir,
		Htpasswd:       "example/htpasswd",
		CookieLifetime: time.Duration(10) * time.Second,
		Secure:         false,
	}
	ts := httptest.NewServer(srv.Mux())
	return srv, dir, ts
}

func getCSRFToken(t *testing.T, ts *httptest.Server, cl *http.Client, path string) string {
	t.Helper()

	resp, err := cl.Get(ts.URL + path)
	require.NoError(t, err)
	defer resp.Body.Close()

	return resp.Header.Get("X-CSRF-Token")
}

func loginRequest(t *testing.T, ts *httptest.Server, cl *http.Client, user, password, redirect string) *http.Request {
	t.Helper()

	params := url.Values{}
	params.Set("login", user)
	params.Set("password", password)
	if redirect != "" {
		params.Set("redirect", redirect)
	}

	enc := params.Encode()
	req, err := http.NewRequest("POST", ts.URL+"/login/", strings.NewReader(enc))
	require.NoError(t, err)
	req.Header.Set("X-CSRF-Token", getCSRFToken(t, ts, cl, "/login/"))
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	return req
}

func sessionCookie(cookies []*http.Cookie) string {
	for _, cookie := range cookies {
		if cookie.Name == "_htpasswd_auth" {
			return cookie.Value
		}
	}
	return ""
}

func TestGoodLogin(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Now()}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	require.NoError(t, err)
	cl := &http.Client{Jar: cj}
	req := loginRequest(t, ts, cl, "test@example.com", "test", "")
	resp, err := cl.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Login should have succeeded")
	t.Log(resp.Cookies())
	if assert.NotEmpty(t, resp.Cookies()) {
		assert.NotEqual(t, "nope", resp.Cookies()[0].Value)
	}

	u, _ := url.Parse(ts.URL)
	t.Log(cj.Cookies(u))

	resp, err = cl.Get(ts.URL + "/auth")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Should be authenticated, but I'm not")
}

func TestGoodLoginWithRedirect(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Now()}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	require.NoError(t, err)
	cl := &http.Client{
		Jar: cj,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req := loginRequest(t, ts, cl, "test@example.com", "test", "https://example.com/redirected-to")
	resp, err := cl.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, "Login should have succeeded & redirected")
	assert.Equal(t, "https://example.com/redirected-to", resp.Header.Get("Location"))
	t.Log(resp.Cookies())
	if assert.NotEmpty(t, resp.Cookies()) {
		assert.NotEqual(t, "nope", resp.Cookies()[0].Value)
	}

	u, _ := url.Parse(ts.URL)
	t.Log(cj.Cookies(u))

	resp, err = cl.Get(ts.URL + "/auth")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Should be authenticated, but I'm not")
}

func TestBadLogin(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Jar: cj}

	req := loginRequest(t, ts, cl, "test@example.com", "wrongpassword", "https://example.com")
	resp, err := cl.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Login should have failed")
}

func TestExpiredSession(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	srv, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Jar: cj}

	// Log us in:
	req := loginRequest(t, ts, cl, "test@example.com", "test", "https://example.com")
	resp, err := cl.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"Should be authenticated, am not: %v", resp)

	// Try using the session in a while:
	ti.at = ti.at.Add(time.Duration(5) * time.Second).Add(srv.CookieLifetime)
	resp, err = cl.Get(ts.URL + "/auth")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"Should no longer be authenticated, but I am: %v and %v", resp, cj)
}

func TestBadDomain(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Jar: cj}
	req := loginRequest(t, ts, cl, "test@example.com", "test", "https://example.com")
	// Replace "127.0.0.1" from the test server with "localhost" -
	// it's the same host (usually), but a different name.
	// NOTE: This assumes that local DNS resolution for
	// "localhost" works correctly; if yours doesn't, this test
	// will fail:
	req.URL.Host = strings.Replace(req.URL.Host, "127.0.0.1", "localhost", 1)
	resp, err := cl.Do(req)
	require.NoError(t, err)
	// The CSRF protection will prevent this from working, as the cookie is no longer valid.
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"Should be authenticated, am not: %v", resp)

	resp, err = cl.Get(ts.URL + "/auth")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"Should not be authenticated under this domain, but I am: %v and %v", resp, cj)
}

func TestLogout(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)
	cj, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cl := &http.Client{Jar: cj}

	req := loginRequest(t, ts, cl, "test@example.com", "test", "https://example.com")
	resp, err := cl.Do(req)
	require.NoError(t, err)

	req, err = http.NewRequest("POST", ts.URL+"/logout", nil)
	require.NoError(t, err)
	req.Header.Set("X-CSRF-Token", getCSRFToken(t, ts, cl, "/logout"))
	resp, err = cl.Do(req)
	require.NoError(t, err)

	resp, err = cl.Get(ts.URL + "/auth")
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMalice(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	srv, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)
	cj, err := cookiejar.New(nil)
	require.NoError(t, err)

	cl := &http.Client{Jar: cj}
	req := loginRequest(t, ts, cl, "test@example.com", "test", "https://example.com")
	resp, err := cl.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	session := sessionCookie(cj.Cookies(req.URL))
	require.NotEmpty(t, session)

	u, _ := url.Parse(ts.URL)
	_, err = srv.ValidatedSessionFromStorage(dir+"/"+session, u.Host)
	assert.Error(t, err)

	relative := filepath.Join("../", filepath.Base(dir), session)
	_, err = srv.ValidatedSessionFromStorage(relative, u.Host)
	assert.Error(t, err, "relative")

	slashes := "////" + dir + "/" + session
	_, err = os.Stat(slashes)
	assert.False(t, os.IsNotExist(err), "slashes file doesn't exist")

	_, err = srv.ValidatedSessionFromStorage("////"+dir+"/"+session, u.Host)
	assert.Error(t, err, "///// validated but shouldn't")
}

func TestLoginRedirectValid(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)
	cj, _ := cookiejar.New(nil)
	cl := &http.Client{
		Jar:           cj,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest("GET", ts.URL+"/auth", nil)
	require.NoError(t, err)

	redirURL := "/wheee"
	resp, err := cl.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	req = loginRequest(t, ts, cl, "test@example.com", "test", redirURL)
	resp, err = cl.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode, "Should be redirected post successful authentication")

	loc, err := resp.Location()
	assert.NoError(t, err)
	assert.Equal(t, redirURL, loc.Path, "Didn't get redirected to the right place")
}

func TestLoginRedirectNoData(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, _ := cookiejar.New(nil)
	cl := &http.Client{
		Jar:           cj,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	req := loginRequest(t, ts, cl, "test@example.com", "test", "")
	resp, err := cl.Do(req)
	assert.NoError(t, err)

	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"Should be authenticated and not redirected, but: %v", resp)
}

func TestGoodHTTPBasicAuth(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Now()}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	require.NoError(t, err)
	cl := http.Client{Jar: cj}

	req, err := http.NewRequest("GET", ts.URL+"/auth", nil)
	require.NoError(t, err)
	req.SetBasicAuth("test@example.com", "test")
	resp, err := cl.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Should be authenticated!")
	assert.Empty(t, sessionCookie(resp.Cookies()), "Should not have received cookies back")
}

func TestBadHTTPBasicAuth(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Now()}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	require.NoError(t, err)
	cl := http.Client{Jar: cj}

	req, err := http.NewRequest("GET", ts.URL+"/auth", nil)
	require.NoError(t, err)
	req.SetBasicAuth("test@example.com", "wrongpass")
	resp, err := cl.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should not be authenticated!")
	session := sessionCookie(resp.Cookies())
	if assert.NotEmpty(t, session) {
		assert.Equal(t, "nope", session)
	}
}
