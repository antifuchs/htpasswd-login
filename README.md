# A minimal nginx `auth_request` authentication service, based on cookies and htpasswd.
[![Build Status](https://travis-ci.org/antifuchs/htpasswd-login.svg?branch=master)](https://travis-ci.org/antifuchs/htpasswd-login)

This little go tool can be used as an authentication service for
nginx's
[`ngx_http_auth_request_module`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html). This
means that if you run nginx and you have few users (and few-enough
sessions), you can run this service next to an actual service you're
running and have `htpasswd-login` run a RESTful service for
authentication and even serve up a customizable authentication form.


## Installation / running this

You can `go get -u github.com/antifuchs/htpasswd-login` and you should
end up with a `htpasswd-login` binary in your `$GOPATH/bin`.

Once installed, you can try out this service on the commandline like this (assuming `/tmp/sessions` exists):

`htpasswd-login --sessions /tmp/sessions --htpasswd example/htpasswd --secure=false --loginform=example/page`

See [example/README.md](example/README.md) for details.

In deployment (if you're running on HTTPS,
which [you should](https://letsencrypt.org)), *please* run this with
`--secure=true` so that no cookies leak over insecure channels.

## Configuring nginx

TK TK TK

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

### Why not build authentication into a the thing you're running behind the scenes?

That mostly has to do with the amount of trust I'm willing to place in
the backend program: If that has a preauth bug, there's a
problem. (That said, if this program has a preauth bug, I would love
to [hear about it!](./CONTRIBUTING.md))
