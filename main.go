package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/base64"
	"encoding/json"

	"github.com/abbot/go-http-auth"
	"github.com/dchest/uniuri"
	"github.com/zenazn/goji/bind"
	"goji.io"
	"goji.io/pat"
)

const cookieName string = "_htpasswd_auth"
const sessionFormat string = time.RFC3339
const slack time.Duration = time.Duration(10) * time.Second

var sessionDir string
var domain string
var htpasswd string
var realm string
var cookieLifetime int

var validChars map[rune]bool

func init() {
	validChars = map[rune]bool{}
	for _, c := range string(uniuri.StdChars) {
		validChars[c] = true
	}
}

type session struct {
	CreatedRaw string `json:"created"`
	Domain     string

	Name    string    `json:"-"`
	Created time.Time `json:"-"`
}

func (s *session) Valid() bool {
	sessionExpiry := s.Created.Add(time.Duration(cookieLifetime) * time.Second)
	return sessionExpiry.After(time.Now())
}
func validateCookie(cookie string) (*session, error) {
	for _, c := range cookie {
		if _, ok := validChars[c]; !ok {
			return nil, errors.New("Cookie value contains invalid characters.")
		}
	}
	sessionPath := filepath.Join(sessionDir, cookie)
	base, err := filepath.Rel(sessionDir, sessionPath)
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
	session := session{Name: cookie}
	json.Unmarshal(data, &session)
	sessionStart, err := time.Parse(sessionFormat, string(session.CreatedRaw))
	if err != nil {
		os.Remove(sessionPath) // clean up the session
		return nil, err
	}
	session.Created = sessionStart
	if !session.Valid() {
		return nil, errors.New("Session is no longer valid.")
	}
	return &session, nil
}

func invalidateCookie() *http.Cookie {
	return &http.Cookie{Name: cookieName, Value: "nope", Domain: domain, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true}
}

func checkSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	newCookie := invalidateCookie()
	success := false

	// Cleanup and ensure we always send a decent response:
	defer func() {
		if !success {
			http.SetCookie(w, newCookie)
			http.Error(w, "Session is not/no longer valid", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte{})
	}()
	if err != nil {
		if err == http.ErrNoCookie {
			return
		}
	}
	session, err := validateCookie(cookie.Value)
	if err != nil {
		log.Printf("Error validating session: %s", err)
		return
	}

	if session.Domain != r.Host {
		log.Printf("Session %q was made for another domain: %s; wanted %q", cookie.Value, session.Domain, r.Host)
		return
	}

	// We have a valid session that hasn't yet expired. Let's call it a success.
	success = true
	return
}

func newSession(domain string) (string, error) {
	name := uniuri.NewLen(90)
	sessionPath := filepath.Join(sessionDir, name)
	data, err := json.Marshal(session{CreatedRaw: time.Now().Add(slack).Format(sessionFormat), Domain: domain})
	if err != nil {
		return "", err
	}
	err = ioutil.WriteFile(sessionPath, data, 0400)
	if err != nil {
		return "", err
	}
	return name, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	newCookie := invalidateCookie()
	success := false
	defer func() {
		http.SetCookie(w, newCookie)
		if !success {
			http.Error(w, "Nope", http.StatusUnauthorized)
			return
		}
	}()
	user := r.PostFormValue("login")
	if len(user) == 0 {
		return
	}

	password := r.PostFormValue("password")
	if len(password) == 0 {
		return
	}

	log.Printf("Validating login request by user %q on %q", user, r.Host)

	// This is very awful, but sadly go-http-auth has no better interface:
	authenticator := auth.NewBasicAuthenticator(realm, auth.HtpasswdFileProvider(htpasswd))
	r.Header["Authorization"] = []string{
		fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, password)))),
	}
	if user != authenticator.CheckAuth(r) {
		log.Printf("User %q couldn't be authenticated", user)
		return
	}

	// OK, we're authenticated. Let's get a session started:
	session, err := newSession(r.Host)
	if err != nil {
		return
	}
	newCookie.Value = session
	newCookie.MaxAge = cookieLifetime
	if r.PostFormValue("ephemeral") == "" {
		newCookie.Expires = time.Now().Add(time.Duration(cookieLifetime) * time.Second)
	}
	success = true
}

func main() {
	bind.DefaultBind = "127.0.0.1:8000"
	flag.StringVar(&sessionDir, "sessions", "/var/db/http-auth/cookies", "Directory in which htpasswd-login-form places sessions")
	flag.StringVar(&domain, "domain", "", "Domain to set on all cookies")
	flag.StringVar(&htpasswd, "htpasswd", "/etc/nginx/.htpasswd", "htpasswd file to use for authentication")
	flag.StringVar(&realm, "realm", "example.com", "HTTP Basic auth realm to pretend we run in")
	flag.IntVar(&cookieLifetime, "lifetime", 86400, "Maximum cookie lifetime in seconds")
	bind.WithFlag()
	flag.Parse()

	mux := goji.NewMux()
	mux.HandleFunc(pat.Get("/auth"), checkSession)
	mux.HandleFunc(pat.Post("/login"), login)

	http.Serve(bind.Default(), mux)

}
