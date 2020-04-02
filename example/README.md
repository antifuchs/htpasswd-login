This directory includes a htpasswd file and an example login page so
you can try out how this might work in practice. (Or just use the form
when you install this in your nginx, that's fine too).

## Usage

Run the `htpasswd-login-form` program with the flags `-loginform
./example/page -htpasswd ./example/htpasswd` and navigate to
http://127.0.0.1:8000/login/.

The test login is `test@example.com` and the password is `test`.

To test the logout flow, navigate to
http://127.0.0.1:8000/logout/


## Inspiration and design

This form uses the fantastic [water.css (light
theme)](https://kognise.github.io/water.css/) classless stylesheet.

I have tried to make this form as accessible as possible - tab indexes
should make sense, autofocusing happens, and the entire form ought to
be screen-readable (although I haven't tested this). Please send me
patches if this isn't working for you!

### Development / updating the stylesheet

To update the vendored `water.css` file, follow the [install
instructions](https://github.com/kognise/water.css#compiling-your-own-theme)
and copy the `light.min.css` and `light.min.css.map` files to the `page/`
subdirectory here.
