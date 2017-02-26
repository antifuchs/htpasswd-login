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
		CookieLifetime: time.Duration(1000) * time.Second,
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
	if err != nil {
		t.Fatal(err)
	}
	cl := http.Client{Jar: cj}
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	resp, err := cl.PostForm(ts.URL+"/login/", params)
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Login should have succeeded: %v", resp)
	}
	t.Log(resp.Cookies())
	if len(resp.Cookies()) == 0 || resp.Cookies()[0].Value == "nope" {
		t.Errorf("I bad cookies: %#v", resp.Cookies())
	}

	u, _ := url.Parse(ts.URL)
	t.Log(cj.Cookies(u))

	resp, err = cl.Get(ts.URL + "/auth")
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Should be authenticated, am not: %v", resp)
	}
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
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Should have failed: %v", resp)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Should be authenticated, am not: %v", resp)
	}

	ti.at = ti.at.Add(time.Duration(5) * time.Second).Add(srv.CookieLifetime)
	resp, err = cl.Get(ts.URL + "/auth")
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("Should no longer be authenticated, but I am: %v and %v", resp, cj)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Should be authenticated, am not: %v", resp)
	}

	resp, err = cl.Get(ts.URL + "/auth")
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Errorf("Should not be authenticated under this domain, but I am: %v and %v", resp, cj)
	}
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
	if err != nil {
		t.Error(err)
	}

	// redirects god-knows-where, so no error checking:
	cl.PostForm(ts.URL+"/logout", url.Values{})

	resp, err := cl.Get(ts.URL + "/auth")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Should be unauthenticated, am not: %v", resp)
	}
}

func TestMalice(t *testing.T) {
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
	if err != nil {
		t.Error(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Should be authenticated, am not: %v", resp)
	}
	session := resp.Cookies()[0].Value
	u, _ := url.Parse(ts.URL)
	_, err = srv.ValidatedSessionFromStorage(dir+"/"+session, u.Host)
	if err == nil {
		t.Error(dir)
	}

	relative := filepath.Join("../", filepath.Base(dir), session)
	_, err = srv.ValidatedSessionFromStorage(relative, u.Host)
	if err == nil {
		t.Error("relative", relative)
	}

	slashes := "////" + dir + "/" + session
	if _, err := os.Stat(slashes); os.IsNotExist(err) {
		t.Error("slashes file doesn't exist")
	}
	_, err = srv.ValidatedSessionFromStorage("////"+dir+"/"+session, u.Host)
	if err == nil {
		t.Error("/////")
	}
}
