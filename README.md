# A minimal nginx `auth_request` authentication service, based on cookies and htpasswd.
[![Build Status](https://travis-ci.org/antifuchs/htpasswd-login.svg?branch=master)](https://travis-ci.org/antifuchs/htpasswd-login)

This little go tool can be used as an authentication service for
nginx's
[`ngx_http_auth_request_module`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html),
verifying that session cookies are valid and allowing users to log in
and have their data validated against
a
[`.htpasswd`](https://httpd.apache.org/docs/current/programs/htpasswd.html) file.

This means that if you run nginx and you have few users (and
few-enough sessions), you can run this service next to an actual
service you're running and have `htpasswd-login` run a RESTful service
for authentication and even serve up a customizable authentication
form.

## Installation / running this

`htpasswd-login` requires a go modules to build, so a recent go
checkout is recommended - in CI, this tool builds with go 1.14.x.

You can `go get -u github.com/antifuchs/htpasswd-login` and you should
end up with a `htpasswd-login` binary in your `$GOBIN` directory.

Once installed, you can try out this service on the commandline like this (assuming `/tmp/sessions` exists):

`htpasswd-login --sessions /tmp/sessions --htpasswd example/htpasswd --secure=false --loginform=example/page`

See [example/README.md](example/README.md) for details.

Once the login form looks like you think it should, deploy this to be
visible to the big, bad internet. The following sections are (in order
of importance) what you will definitely need to do:

### Use HTTPS

In deployment (if you're running on HTTPS, which [you
should](https://letsencrypt.org)), *please* run this with
`--secure=true` so that no cookies leak over insecure channels.

### Configure a CSRF secret

`htpasswd-login` uses [CSRF
protection](https://blog.codinghorror.com/preventing-csrf-and-xsrf-attacks/)
to hopefully prevent some easy avenues for phishing from authenticated
sites. You should generate a CSRF secret and re-use this (otherwise
login forms served to clients will no longer be submittable if you
restart the server).

To generate a secret once, use
`dd if=/dev/urandom bs=32 count=1 | openssl base64 > csrf-secret.b64`

Then, to use that secret, pass the `--csrf="$(cat csrf-secret.b64)"`
flag to htpasswd-login.

### Set up a cron job to clean out old sessions

Once this is working for you, make sure to run the tool with the same
arguments as you run the frontend with, and add `-cleanup` in a cron
job once an hour or so, in order to clean out old sessions.

## Configuring nginx

See the file [auth_request.inc.conf](example/auth_request.inc.conf)
in examples for an example config. Note that in addition to including
this file in your `server` blocks, you'll also have to have an
`auth_request /auth` stanza in every `location` block you wish to
protect.

## Limits & Operation

This tool is meant for personal use, and specifically constrains
itself to some design choices that you shouldn't make when running
this on a larger scale. Here are the assumptions I've made:

* You don't have very many users. Credential lookup is O(n), which
  means that more users will make logins slow.

* Each user doesn't have very many sessions. We store sessions in a
  directory, which means that as the total number of sessions grows
  into the many thousands, looking up those sessions will get slower
  (and may slow down your overall system).

* You should run `-cleanup` regularly, to remove old sessions.


## Why?

You obviously have questions. I have reasons for building this. (And I
would have loved not to have to build this!) Here goes:

### Why not just use HTTP Basic authentication?

That's a good
question:
[HTTP Basic authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) is
quite simple, and if you can use it, you probably should!

However, Basic auth has some drawbacks:

* Most browsers present a UI that isn't suitable for password managers

* Some backend programs are not completely able to deal with living
  behind Basic auth: Some generate URLs that just don't work.

I think this tool combines the nicest advantages of HTTP Basic
authentication (namely, that you can use `.htpasswd` files, which are
very well understood and easy to manipulate), with a nice and
accessible way for your users to log in.

As an accomodation for native apps that act as API clients, requests
bearing an HTTP Basic `Authorization` header matching the credentials
in the `.htpasswd` file count as authenticated. So you *can* use Basic
authentication, however your users won't receive a login prompt.

### Why not build authentication into a the thing you're running behind the scenes?

That mostly has to do with the amount of trust I'm willing to place in
the backend program: If that has a preauth bug, there's a
problem. (That said, if this program has a preauth bug, I would love
to [hear about it!](./CONTRIBUTING.md))
