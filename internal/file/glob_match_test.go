package file

import (
	"strings"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	var tests = []struct {
		pattern string
		data    string
		ok      bool
	}{
		{"", "", true},
		{"x", "", false},
		{"", "x", false},
		{"abc", "abc", true},
		{"*", "abc", true},
		{"*c", "abc", true},
		{"*b", "abc", false},
		{"a*", "abc", true},
		{"b*", "abc", false},
		{"a*", "a", true},
		{"*a", "a", true},
		{"a*b*c*d*e*", "axbxcxdxe", true},
		{"a*b*c*d*e*", "axbxcxdxexxx", true},
		{"a*b?c*x", "abxbbxdbxebxczzx", true},
		{"a*b?c*x", "abxbbxdbxebxczzy", false},
		{"a*a*a*a*b", strings.Repeat("a", 100), false},
		{"*x", "xxx", true},
		{"/home/place/**", "/home/place/a/thing", true},
	}

	for _, test := range tests {
		if GlobMatch(test.pattern, test.data) != test.ok {
			t.Errorf("failed glob='%s' data='%s'", test.pattern, test.data)
		}
	}
}
