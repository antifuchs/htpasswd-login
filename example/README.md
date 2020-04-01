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

The form and styling are inspired by excellent login form
template](http://codepen.io/colorlib/pen/rxddKy)
and
[this page on how to create styled checkboxes](http://www.inserthtml.com/2012/06/custom-form-radio-checkbox/). All
the the good design is theirs, all ugliness was added by me (and I'm
very sorry).

I have tried to make this as accessible as possible - tab indexes
should make sense, autofocusing happens, and the entire form ought to
be screen-readable (although I haven't tested this). Please send me
patches if this isn't working for you!
