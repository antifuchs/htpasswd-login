package htpasswd

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	auth "github.com/abbot/go-http-auth"

	goji "goji.io"
	"goji.io/pat"
)

var defaultLoginForm = template.Must(template.New("index.html.tmpl").Parse(
	`<!doctype html>
<html>
  <head>
    <title>Login</title>
    <link rel="stylesheet" type="text/css" href="style.css">
  </head>
  <body>
    <div class="login-page">
      <div class="form">
	<form method="post" class="login-form">
	  <section class="basic-info">
	    <input type="email" name="login" placeholder="email address" tabindex="1" autofocus required>
	    <input type="password" name="password" placeholder="password" tabindex="2" required>
	    <input type="hidden" name="redirect" value="{{ .Redirect }}">
	    <input type="submit" tabindex="4" value="Login">
	  </section>
	  <p class="message">
	    <input tabindex="3" class="regular-checkbox" type="checkbox" id="ephemeral" name="ephemeral">
	    <label  for="ephemeral">This is a public computer</label>
	  </p>
	</form>
      </div>
    </div>
  </body>
</html>
`))

// Mux constructs a goji mux that performs authentication with the
// service.
func (srv *Service) Mux() *goji.Mux {
	mux := goji.NewMux()
	mux.HandleFunc(pat.Get("/auth"), srv.checkSession)
	mux.HandleFunc(pat.Post("/login/"), srv.login)
	mux.HandleFunc(pat.Post("/logout"), srv.logout)
	setupIndexTemplate(mux, srv.StaticsDir)

	if srv.StaticsDir != "" {
		statics := http.FileServer(http.Dir(srv.StaticsDir))
		mux.Handle(pat.Get("/login/*"), http.StripPrefix("/login/", statics))
	}
	return mux
}

func setupIndexTemplate(mux *goji.Mux, dir string) {
	tf := filepath.Join(dir, "index.html.tmpl")
	tmpl := defaultLoginForm
	if _, err := os.Stat(tf); dir != "" && err == nil {
		tmpl = template.Must(template.ParseFiles(tf))
	}
	tmpl.Option("missingkey=error")
	index := func(w http.ResponseWriter, r *http.Request) {
		originalURI := r.FormValue("redirect")
		tmpl.Execute(w, struct {
			Redirect string
		}{originalURI})
	}
	mux.HandleFunc(pat.Get("/login/"), index)
	mux.HandleFunc(pat.Get("/login/index.html"), index)
	mux.HandleFunc(pat.Get("/login/index.html.tmpl"), func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login/index.html", http.StatusMovedPermanently)
	})
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
			log.Printf("Failed to authenticate.")
			http.Error(w, "Nope", http.StatusForbidden)
			return
		}
		url := srv.redirectTarget(r)
		if url == "" {
			log.Print("Authenticated, but no redirect target")
			fmt.Fprint(w, "OK!")
			return
		}
		log.Printf("Authenticated, redirecting to %q", url)
		http.Redirect(w, r, url, http.StatusSeeOther)
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
