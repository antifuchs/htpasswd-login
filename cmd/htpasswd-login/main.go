package main

import (
	"flag"
	"net/http"
	"time"

	htpasswd "github.com/antifuchs/htpasswd-login"
	"github.com/zenazn/goji/bind"
)

func main() {
	var cleanup bool

	bind.DefaultBind = "127.0.0.1:8000"

	srv := htpasswd.Service{}

	bind.WithFlag()
	flag.StringVar(&srv.SessionDir, "sessions", "/var/db/http-auth/cookies", "Directory in which htpasswd-login places sessions")
	flag.StringVar(&srv.Htpasswd, "htpasswd", "/etc/nginx/.htpasswd", "htpasswd file to use for authentication")
	var cookieLife int
	flag.IntVar(&cookieLife, "lifetime", 86400, "Maximum cookie lifetime in seconds")
	flag.BoolVar(&srv.Secure, "secure", true, "Whether to set cookies to secure (false is useful for dev)")
	flag.StringVar(&srv.StaticsDir, "loginform", "", "Directory to serve statics from. /index.html should be the form itself.")
	flag.BoolVar(&cleanup, "cleanup", false, "Perform once-in-a-while cleanup actions")
	flag.Parse()
	srv.CookieLifetime = time.Duration(cookieLife) * time.Second

	if cleanup {
		srv.RunCleanup()
		return
	}

	http.Serve(bind.Default(), srv.Mux())
}
