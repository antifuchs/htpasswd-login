//go:generate statik -src=example/page -include=*.css,*.map,*.html -p=statics
//go:generate statik -src=example/page -include=*.tmpl -ns=templates -p=templates

package htpasswd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	_ "github.com/antifuchs/htpasswd-login/statics"
	_ "github.com/antifuchs/htpasswd-login/templates"

	auth "github.com/abbot/go-http-auth"
	"github.com/rakyll/statik/fs"

	"github.com/gorilla/csrf"
	goji "goji.io"
	"goji.io/pat"
)

var templateFS = mustTemplateFS()

func mustTemplateFS() http.FileSystem {
	statikFS, err := fs.NewWithNamespace("templates")
	if err != nil {
		log.Fatal(err)
	}
	return statikFS
}

func mustTemplateFromStatics(name string) *template.Template {
	data, err := fs.ReadFile(templateFS, name)
	if err != nil {
		log.Fatalf("Could not read template %q: %v", name, err)
	}
	return template.Must(template.New(path.Base(name)).Parse(string(data)))
}

var defaultLoginForm = mustTemplateFromStatics("/index.html.tmpl")
var defaultLogoutForm = mustTemplateFromStatics("/logout.html.tmpl")

func csrfError(w http.ResponseWriter, r *http.Request) {
	log.Printf("CSRF validation failure - %v; headers %v", csrf.FailureReason(r), r.Header)
	http.Error(w, fmt.Sprintf("Forbidden - %v", csrf.FailureReason(r)),
		http.StatusForbidden)
}

// Mux constructs a goji mux that performs authentication with the
// service.
func (srv *Service) Mux() *goji.Mux {
	mux := goji.NewMux()

	mux.Use(csrf.Protect(srv.secretToken(),
		csrf.Secure(srv.Secure),
		csrf.ErrorHandler(http.HandlerFunc(csrfError))))
	mux.HandleFunc(pat.Get("/auth"), srv.checkSession)

	mux.HandleFunc(pat.Post("/login/"), srv.login)
	mux.HandleFunc(pat.Post("/login"), srv.login)

	mux.HandleFunc(pat.Post("/logout/"), srv.logout)
	mux.HandleFunc(pat.Post("/logout"), srv.logout)
	setupIndexTemplate(mux, srv.StaticsDir)

	statics, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	fs := http.FileServer(statics)
	if srv.StaticsDir != "" {
		fs = http.FileServer(http.Dir(srv.StaticsDir))
	}
	mux.Handle(pat.Get("/login/*"), http.StripPrefix("/login/", fs))
	mux.Handle(pat.Get("/logout/*"), http.StripPrefix("/logout/", fs))
	return mux
}

func setupIndexTemplate(mux *goji.Mux, dir string) {
	logintf := filepath.Join(dir, "index.html.tmpl")
	loginTmpl := defaultLoginForm
	if _, err := os.Stat(logintf); dir != "" && err == nil {
		log.Printf("Using login form template %q", logintf)
		loginTmpl = template.Must(template.ParseFiles(logintf))
	}
	loginTmpl.Option("missingkey=error")
	logouttf := filepath.Join(dir, "logout.html.tmpl")
	logoutTmpl := defaultLogoutForm
	if _, err := os.Stat(logouttf); dir != "" && err == nil {
		log.Printf("Using logout form template %q", logouttf)
		logoutTmpl = template.Must(template.ParseFiles(logouttf))
	}
	logoutTmpl.Option("missingkey=error")

	login := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", csrf.Token(r))
		originalURI := r.FormValue("redirect")
		var b bytes.Buffer
		err := loginTmpl.Execute(&b, struct {
			Redirect  string
			CSRFField template.HTML
		}{originalURI, csrf.TemplateField(r)})
		if err != nil {
			log.Printf("Failed so render login form: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		io.Copy(w, &b)
	}
	logout := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-CSRF-Token", csrf.Token(r))
		var b bytes.Buffer
		err := logoutTmpl.Execute(&b, struct {
			CSRFField template.HTML
		}{csrf.TemplateField(r)})
		if err != nil {
			log.Printf("Failed so render logout form: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		io.Copy(w, &b)
	}
	mux.HandleFunc(pat.Get("/login/"), login)
	mux.HandleFunc(pat.Get("/logout/"), logout)

	// compatibility redirects:
	mux.Handle(pat.Get("/login"), redirector("login/"))
	mux.Handle(pat.Get("/logout"), redirector("logout/"))
	mux.Handle(pat.Get("/login/index.html.tmpl"), redirector("./"))
	mux.Handle(pat.Get("/logout/index.html.tmpl"), redirector("./"))
	mux.Handle(pat.Get("/login/index.html"), redirector("./"))
	mux.Handle(pat.Get("/logout/index.html"), redirector("./"))
}

func redirector(to string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to, http.StatusMovedPermanently)
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
		log.Print("user is empty")
		return
	}

	password := r.PostFormValue("password")
	if len(password) == 0 {
		log.Print("password is empty")
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
