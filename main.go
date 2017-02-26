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
var secure bool

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

func (s *session) fill(name string) error {
	t, err := time.Parse(sessionFormat, s.CreatedRaw)
	if err != nil {
		return err
	}
	s.Created = t
	s.Name = name
	return nil
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
	session := session{}
	json.Unmarshal(data, &session)
	err = session.fill(cookie)
	if err != nil {
		os.Remove(sessionPath) // clean up the session
		return nil, err
	}
	if !session.Valid() {
		return nil, errors.New("Session is no longer valid.")
	}
	return &session, nil
}

func invalidateCookie() *http.Cookie {
	return &http.Cookie{Name: cookieName, Value: "nope", Domain: domain, Path: "/", MaxAge: -1, Secure: secure, HttpOnly: true}
}

func checkSession(w http.ResponseWriter, r *http.Request) {
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

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		if err != http.ErrNoCookie {
			log.Printf("Failed getting the cookie: %s", err)
		}
		return

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
			http.Error(w, "Nope", http.StatusForbidden)
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

func runCleanup() {
	deleted := 0
	err := filepath.Walk(sessionDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if path != sessionDir {
				return filepath.SkipDir
			} else {
				return nil
			}
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		var sess session
		err = json.Unmarshal(data, &sess)
		if err != nil {
			fmt.Printf("Session %q was invalid JSON (%s), leaving it", path, err)
			return nil
		}
		if err = sess.fill(filepath.Base(path)); err != nil {
			fmt.Printf("Session %q has an invalid date (%s), deleting it", path, err)
			return os.Remove(path)
		}
		if !sess.Valid() {
			deleted += 1
			return os.Remove(path)
		}
		return nil
	})
	if err != nil {
		log.Printf("Couldn't delete sessions: %s", err)
		os.Exit(2)
	}
	if deleted > 0 {
		log.Printf("Cleaned out %d sessions from %q.", deleted, sessionDir)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(cookieName)
	http.SetCookie(w, invalidateCookie())
	if err != nil {
		if err != http.ErrNoCookie {
			log.Printf("Failed getting the cookie: %s", err)
		}
		http.Redirect(w, r, "/", 301)
		return
	}

	session, err := validateCookie(cookie.Value)
	if err != nil {
		log.Printf("Error validating session: %s", err)
		http.Redirect(w, r, "/", 301)
		return
	}
	os.Remove(filepath.Join(sessionDir, session.Name))
	http.Redirect(w, r, "/", 301)
}

func main() {
	var cleanup bool

	bind.DefaultBind = "127.0.0.1:8000"
	bind.WithFlag()
	flag.StringVar(&sessionDir, "sessions", "/var/db/http-auth/cookies", "Directory in which htpasswd-login-form places sessions")
	flag.StringVar(&domain, "domain", "", "Domain to set on all cookies")
	flag.StringVar(&htpasswd, "htpasswd", "/etc/nginx/.htpasswd", "htpasswd file to use for authentication")
	flag.StringVar(&realm, "realm", "example.com", "HTTP Basic auth realm to pretend we run in")
	flag.IntVar(&cookieLifetime, "lifetime", 86400, "Maximum cookie lifetime in seconds")
	flag.BoolVar(&secure, "secure", true, "Whether to set cookies to secure (false is useful for dev)")

	flag.BoolVar(&cleanup, "cleanup", false, "Perform once-in-a-while cleanup actions")
	flag.Parse()

	if cleanup {
		runCleanup()
		return
	}

	mux := goji.NewMux()
	mux.HandleFunc(pat.Get("/auth"), checkSession)
	mux.HandleFunc(pat.Post("/login"), login)
	mux.HandleFunc(pat.Post("/logout"), logout)

	http.Serve(bind.Default(), mux)
}
