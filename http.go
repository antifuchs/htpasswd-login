package htpasswd

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	auth "github.com/abbot/go-http-auth"

	goji "goji.io"
	"goji.io/pat"
)

func (srv *Service) Mux() *goji.Mux {
	mux := goji.NewMux()
	mux.HandleFunc(pat.Get("/auth"), srv.checkSession)
	mux.HandleFunc(pat.Post("/login/"), srv.login)
	mux.HandleFunc(pat.Post("/logout"), srv.logout)

	if srv.StaticsDir != "" {
		statics := http.FileServer(http.Dir(srv.StaticsDir))
		mux.Handle(pat.Get("/login/*"), http.StripPrefix("/login/", statics))
	}
	return mux
}

func (srv *Service) checkSession(w http.ResponseWriter, r *http.Request) {
	newCookie := srv.invalidateCookie(r.Host)
	success := false

	if originalURI := r.Header.Get("X-Original-URI"); originalURI != "" {
		redirCookie := srv.redirectCookie(r.Host, originalURI)
		if _, err := r.Cookie(redirCookie.Name); err == http.ErrNoCookie {
			// Mark the place we came from (the first
			// time!) in a cookie, so we know to redirect
			// when logging in:
			http.SetCookie(w, redirCookie)
		}
	}

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
	session, err := srv.ValidatedSessionFromStorage(cookie.Value, r.Host)
	if err != nil {
		log.Printf("Error validating session: %s", err)
		return
	}

	// We have a valid session that hasn't yet expired. Let's call it a success.
	w.Header().Set(usernameHeader, session.Username)
	success = true
	return
}

func (srv *Service) login(w http.ResponseWriter, r *http.Request) {
	newCookie := srv.invalidateCookie(r.Host)
	success := false
	defer func() {
		http.SetCookie(w, newCookie)
		if !success {
			http.Error(w, "Nope", http.StatusForbidden)
			return
		}
		url, err := srv.redirectTarget(r)
		if err != nil || url == "" {
			log.Printf("Couldn't redirect to %q: %s", url, err)
			fmt.Fprint(w, "OK!")
			return
		}
		log.Printf("Redir target: %q", url)
		http.Redirect(w, r, url, 302)
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
	authenticator := auth.NewBasicAuthenticator(realm, auth.HtpasswdFileProvider(srv.Htpasswd))
	r.Header["Authorization"] = []string{
		fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", user, password)))),
	}
	if user != authenticator.CheckAuth(r) {
		log.Printf("User %q couldn't be authenticated", user)
		return
	}

	session, err := srv.NewSession(r.Host, user)
	if err != nil {
		return
	}
	newCookie.Value = session
	if r.PostFormValue("ephemeral") == "" {
		newCookie.Expires = srv.Now().Add(srv.CookieLifetime)
		newCookie.MaxAge = int(srv.CookieLifetime / time.Second)
	} else {
		// Ephemeral session requested - leave off any
		// MaxAge/Expires settings to attempt to make browsers
		// drop the cookie once the session ends:
		newCookie.MaxAge = 0
	}
	success = true
}

func (srv *Service) logout(w http.ResponseWriter, r *http.Request) {
	defer http.SetCookie(w, srv.invalidateCookie(r.Host))

	cookie, err := r.Cookie(cookieName)
	if err != nil {
		if err != http.ErrNoCookie {
			log.Printf("Failed getting the cookie: %s", err)
		}
		http.Redirect(w, r, "/", 301)
		return
	}

	session, err := srv.ValidatedSessionFromStorage(cookie.Value, r.Host)
	if err != nil {
		log.Printf("Error validating session: %s", err)
		http.Redirect(w, r, "/", 301)
		return
	}
	os.Remove(filepath.Join(srv.SessionDir, session.Name))
	http.Redirect(w, r, "/", 301)
}
