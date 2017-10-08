package htpasswd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsParent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected bool
		new      string
		existing string
	}{
		{true, "/", "/favicon.ico"},
		{true, "/whee", "/whee/favicon.ico"},
		{false, "/favicon.ico", "/"},
		{false, "/foo", "/bar"},
		{true, "/foo", "/foo/bar/baz/oink/"},
		{false, "/foo.html", "/bar.html"},
	}
	for _, elt := range tests {
		test := elt
		t.Run(fmt.Sprintf("%v", test), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.expected, isParent(test.new, test.existing), "%v", test)
		})
	}
}

func TestMoreSpecific(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected bool
		new      string
		existing string
	}{
		{"favicon.ico", false, "http://foo.com/favicon.ico", "http://foo.com/"},
		{"/ from favicon", true, "http://foo.com/", "http://foo.com/favicon.ico"},
		{"different host", true, "http://foo.com/", "http://bar.com/"},
		{"different port", true, "http://foo.com/", "http://foo.com:8080/"},
		{"subdir", true, "http://foo.com/foo", "http://foo.com/foo/bar"},
		{"different dir", true, "http://foo.com/bar", "http://foo.com/foo/bar"},
	}
	for _, elt := range tests {
		test := elt
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.expected, moreRelevant(test.new, test.existing), "%q -> %q", test.new, test.existing)
		})
	}
}
