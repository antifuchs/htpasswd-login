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

func TestGoodLogin(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Now()}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, err := cookiejar.New(nil)
	require.NoError(t, err)
	cl := http.Client{Jar: cj}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	resp, err := cl.PostForm(ts.URL+"/login/", params)
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
	cl := http.Client{Jar: cj}

	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "wrongpassword")
	resp, err := cl.PostForm(ts.URL+"/login/", params)
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
	cl := http.Client{Jar: cj}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	resp, err := cl.PostForm(ts.URL+"/login/", params)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"Should be authenticated, am not: %v", resp)

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
	cl := http.Client{Jar: cj}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")

	// Replace "127.0.0.1" from the test server with "localhost" -
	// it's the same host (usually), but a different name.
	// NOTE: This assumes that local DNS resolution for
	// "localhost" works correctly; if yours doesn't, this test
	// will fail:
	otherURL := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	resp, err := cl.PostForm(otherURL+"/login/", params)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
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
	cl := http.Client{Jar: cj}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	_, err = cl.PostForm(ts.URL+"/login/", params)
	assert.NoError(t, err)

	resp, err := cl.PostForm(ts.URL+"/logout", url.Values{})
	require.NoError(t, err)
	defer resp.Body.Close()

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

	cl := http.Client{Jar: cj}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	resp, err := cl.PostForm(ts.URL+"/login/", params)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	session := resp.Cookies()[0].Value
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
	cl := http.Client{Jar: cj, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", ts.URL+"/auth", nil)
	require.NoError(t, err)

	redirURL := "/wheee"
	req.Header.Set("X-Original-URI", redirURL)
	resp, err := cl.Do(req)
	require.NoError(t, err)

	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	resp, err = cl.PostForm(ts.URL+"/login/", params)
	require.NoError(t, err)

	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode, "Should be redirected post successful authentication")

	loc, _ := resp.Location()
	assert.Equal(t, redirURL, loc.Path, "Didn't get redirected to the right place")
}

func TestLoginRedirectMultiple(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)
	cj, _ := cookiejar.New(nil)
	cl := http.Client{Jar: cj, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", ts.URL+"/auth", nil)
	require.NoError(t, err)
	redirURL := "/wheee"
	req.Header.Set("X-Original-URI", ts.URL+redirURL)
	_, err = cl.Do(req)
	require.NoError(t, err)

	req, err = http.NewRequest("GET", ts.URL+"/auth", nil)
	require.NoError(t, err)

	req.Header.Set("X-Original-URI", ts.URL+"/wheee/favicon.ico")
	_, err = cl.Do(req)
	require.NoError(t, err)

	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	resp, err := cl.PostForm(ts.URL+"/login/", params)
	require.NoError(t, err)

	defer resp.Body.Close()
	if assert.Equal(t, http.StatusFound, resp.StatusCode,
		"Should be authenticated and redirected, but: %v", resp) {
		loc, _ := resp.Location()
		assert.Equal(t, redirURL, loc.Path, "Got redirected to the wrong place")
	}
}

func TestLoginRedirectNoData(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	_, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, _ := cookiejar.New(nil)
	cl := http.Client{Jar: cj, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	req, err := http.NewRequest("POST", ts.URL+"/login/", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, err)

	resp, err := cl.Do(req)
	assert.NoError(t, err)

	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"Should be authenticated and not redirected, but: %v", resp)
}

func TestLoginRedirectInvalid(t *testing.T) {
	t.Parallel()
	ti := &timer{at: time.Unix(0, 0)}
	srv, dir, ts := service(t, ti)
	defer ts.Close()
	defer os.RemoveAll(dir)

	cj, _ := cookiejar.New(nil)
	cl := http.Client{Jar: cj, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	req, err := http.NewRequest("POST", ts.URL+"/login/", strings.NewReader(params.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	redirURL := strings.Replace(ts.URL+"/wheee/", "127.0.0.1", "localhost", 1)
	ck := &http.Cookie{
		Name:     "_htpasswd_uri",
		Value:    redirURL,
		Domain:   "127.0.0.1",
		Path:     "/",
		MaxAge:   0,
		Secure:   srv.Secure,
		HttpOnly: true,
	}
	req.AddCookie(ck)

	resp, err := cl.Do(req)
	if assert.NoError(t, err) {
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Should be authenticated, but: %v", resp)

		loc, err := resp.Location()
		assert.Error(t, err)
		assert.Nil(t, loc, "Should not have gotten redirected")
	}
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
	assert.Empty(t, resp.Cookies(), "Should not have received cookies back")
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
	if assert.NotEmpty(t, resp.Cookies()) {
		assert.Equal(t, "nope", resp.Cookies()[0].Value)
	}
}
