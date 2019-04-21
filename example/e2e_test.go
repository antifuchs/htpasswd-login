package example

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

	htpasswd "github.com/antifuchs/htpasswd-login"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2E(t *testing.T) {
	sessions, err := ioutil.TempDir("/tmp", "htpasswd-test")
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(os.ExpandEnv("$GOPATH"), "src/github.com/antifuchs/htpasswd-login/example/page")

	srv := &htpasswd.Service{
		Now:            time.Now,
		SessionDir:     sessions,
		StaticsDir:     dir,
		Htpasswd:       "htpasswd",
		CookieLifetime: time.Duration(10) * time.Second,
		Secure:         false,
	}
	ts := httptest.NewServer(srv.Mux())
	defer ts.Close()
	defer os.RemoveAll(sessions)

	success := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SUCCESS"))
	}))
	defer success.Close()

	redirURL := success.URL

	cj, _ := cookiejar.New(nil)
	cl := http.Client{
		Jar: cj,
	}
	req, _ := http.NewRequest("GET", ts.URL+"/auth", nil)

	// First request --- Try to authenticate:
	resp, err := cl.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Second request -- The login form:
	formURL, _ := url.Parse(ts.URL + "/login/")
	query := url.Values{}
	query.Set("redirect", success.URL) // nginx would set that parameter
	formURL.RawQuery = query.Encode()
	req, _ = http.NewRequest("GET", formURL.String(), nil)
	resp, err = cl.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	form, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(form),
		`<input type="hidden" name="redirect" value="`+redirURL+`">`)

	// Third request -- The authentication attempt:
	params := url.Values{}
	params.Set("login", "test@example.com")
	params.Set("password", "test")
	params.Set("redirect", redirURL)
	resp, err = cl.PostForm(ts.URL+"/login/", params)
	require.NoError(t, err)

	defer resp.Body.Close()
	target, _ := ioutil.ReadAll(resp.Body)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "SUCCESS", string(target))
}
