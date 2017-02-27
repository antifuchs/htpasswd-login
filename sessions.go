package htpasswd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"github.com/dchest/uniuri"
)

const usernameHeader string = "X-Authenticated-Username"
const cookieName string = "_htpasswd_auth"
const origTargetName string = "_htpasswd_uri"
const sessionFormat string = time.RFC3339
const realm string = "example.com"

// Max amount of time we assume that minting a cookie might take - if
// it takes longer, the session is not valid before the browser
// receives it.
const slack time.Duration = time.Duration(-10) * time.Second

var validChars map[rune]bool

func init() {
	validChars = map[rune]bool{}
	for _, c := range string(uniuri.StdChars) {
		validChars[c] = true
	}
}

type Timesource func() time.Time

type Service struct {
	SessionDir     string
	Htpasswd       string
	StaticsDir     string
	CookieLifetime time.Duration
	Secure         bool
	Now            Timesource
}

type session struct {
	Created  time.Time
	Domain   string
	Username string
	Name     string
}

type storedSession struct {
	Created  string
	Domain   string
	Username string
}

// Loads a session structure from disk and returns a plausible-looking
// session that might be expired or have an invalid domain. You
// probably want Service.ValidatedSessionFromStorage instead.
func (srv *Service) unvalidatedSessionFromStorage(cookie string) (*session, error) {
	for _, c := range cookie {
		if _, ok := validChars[c]; !ok {
			return nil, errors.New("Cookie value contains invalid characters.")
		}
	}
	sessionPath := filepath.Join(srv.SessionDir, cookie)
	base, err := filepath.Rel(srv.SessionDir, sessionPath)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(base, ".") || strings.HasPrefix(base, "/") {
		return nil, errors.New("Cookie value would traverse directories")
	}

	// From here on, the session pathname is assumed innocent & handle-able.
	data, err := ioutil.ReadFile(sessionPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Request for a session that doesn't exist: %q", sessionPath)
			return nil, err
		} else {
			log.Printf("Checking session %q failed: %s", sessionPath, err)
			return nil, err
		}
	}
	sj := storedSession{}
	err = json.Unmarshal(data, &sj)
	if err != nil {
		return nil, err
	}
	session := session{
		Domain:   sj.Domain,
		Username: sj.Username,
		Name:     cookie,
	}
	t, err := time.Parse(sessionFormat, sj.Created)
	if err != nil {
		return nil, err
	}
	session.Created = t
	return &session, err
}

// Loads a session structure from disk and checks it for validity. If
// this returns a nil error, the session is valid, for the expected
// hostname, and is not expired.
func (srv *Service) ValidatedSessionFromStorage(cookie, host string) (*session, error) {
	session, err := srv.unvalidatedSessionFromStorage(cookie)
	if err != nil {
		return nil, err
	}
	if err := session.Valid(srv.Now, srv.CookieLifetime, host); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *session) ExpiredAt(when time.Time, lifetime time.Duration) bool {
	sessionExpiry := s.Created.Add(lifetime)
	return !sessionExpiry.After(when)
}

// Checks that a given session object is not expired and minted for
// the expected host.
func (s *session) Valid(now Timesource, lifetime time.Duration, host string) error {
	if s.ExpiredAt(now(), lifetime) {
		return errors.New("Session is no longer valid.")
	}

	if s.Domain != host {
		return fmt.Errorf("Session hostname %q does not match the request hostname %q.", s.Domain, host)
	}
	return nil
}

func (srv *Service) redirectTarget(r *http.Request) (string, error) {
	cookie, err := r.Cookie(origTargetName)
	if err != nil {
		if err == http.ErrNoCookie {
			return "", nil
		}
		return "", err
	}
	u, err := url.Parse(cookie.Value)
	if err != nil {
		return "", err
	}
	if u.Host != r.Host {
		return "", fmt.Errorf("Redirect cookie %q didn't match the host we expected: %q", u.Host, r.Host)
	}
	return cookie.Value, nil
}

func (srv *Service) redirectCookie(host, uri string) *http.Cookie {
	return &http.Cookie{
		Name:     origTargetName,
		Value:    uri,
		Domain:   host,
		Path:     "/",
		MaxAge:   0,
		Secure:   srv.Secure,
		HttpOnly: true,
	}
}

func (srv *Service) invalidateCookie(host string) *http.Cookie {
	return &http.Cookie{
		Name:     cookieName,
		Value:    "nope",
		Domain:   host,
		Path:     "/",
		MaxAge:   -1,
		Secure:   srv.Secure,
		HttpOnly: true,
	}
}

func (srv *Service) newSession(domain, user string) (string, error) {
	name := uniuri.NewLen(90)
	sessionPath := filepath.Join(srv.SessionDir, name)
	data, err := json.Marshal(storedSession{
		Created:  srv.Now().Add(slack).Format(sessionFormat),
		Domain:   domain,
		Username: user,
	})
	if err != nil {
		return "", err
	}
	err = ioutil.WriteFile(sessionPath, data, 0400)
	if err != nil {
		return "", err
	}
	return name, nil
}
