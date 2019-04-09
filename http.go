package htpasswd

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	auth "github.com/abbot/go-http-auth"

	"net/url"

	goji "goji.io"
	"goji.io/pat"
)

// Mux constructs a goji mux that performs authentication with the
// service.
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

func isParent(new, existing string) bool {
	for ; existing != "/" && existing != ""; existing = path.Dir(existing) {
		if new == existing || new+"/" == existing {
			return true
		}
	}
	return existing == new
}

// Checks if a URL is more relevant (that is, has less qualifiers)
// than another. It returns true if newStr is more specific than
// existingStr. This is a heuristic based on my experience with the
// way browsers make requests to sites behind htpasswd_auth; it will
// likely break if you have framesets with references in the
// right/wrong places, or other edge cases.
func moreRelevant(newStr, existingStr string) bool {
	new, err := url.Parse(newStr)
	if err != nil {
		return false
	}
	existing, err := url.Parse(existingStr)
	if err != nil {
		return true
	}

	// If the new URL is in a completely different location, it's
	// more specific:
	if existing.Host != new.Host || existing.Scheme != new.Scheme {
		return true
	}

	// If the new URL's path is an ancestor of the existing one
	// (or it's a completely different dir altogether), it's more
	// specific:
	return isParent(new.Path, existing.Path) || !isParent(existing.Path, new.Path)
}

func (srv *Service) hasCorrectBasicAuth(r *http.Request) bool {
	if _, _, ok := r.BasicAuth(); ok {
		authenticator := auth.NewBasicAuthenticator(realm, auth.HtpasswdFileProvider(srv.Htpasswd))
		return authenticator.CheckAuth(r) != ""
	}
	return false
}

func (srv *Service) checkSession(w http.ResponseWriter, r *http.Request) {
	// Short-circuit setting up a session when the request holds
	// the correct HTTP basic auth (e.g. it's an API client):
	if srv.hasCorrectBasicAuth(r) {
		w.WriteHeader(http.StatusOK)
		return
	}

	newCookie := srv.invalidateCookie(r.Host)
	success := false

	if originalURI := r.Header.Get("X-Original-URI"); originalURI != "" {
		redirCookie := srv.redirectCookie(r.Host, originalURI)
		existing, err := r.Cookie(redirCookie.Name)
		if err == http.ErrNoCookie || moreRelevant(originalURI, existing.Value) {
			// Mark the place we came from (if the user
			// visited a page more specific than any
			// existing earmarked one, e.g. / after
			// visiting /favicon.ico) in a cookie, so we
			// know to redirect when logging in:
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
		w.WriteHeader(http.StatusOK)
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
	err = os.Remove(filepath.Join(srv.SessionDir, session.Name))
	if err != nil {
		// This is relatively peaceful, provided the client
		// throws away the session cookie:
		log.Printf("Error deleting session file on logout: %v", err)
	}
	http.Redirect(w, r, "/", 301)
}
