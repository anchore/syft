package php

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		packageVersion string
		expected       string
	}{
		{
			name:           "with extractable vendor",
			packageName:    "ven/name",
			packageVersion: "1.0.1",
			expected:       "pkg:composer/ven/name@1.0.1",
		},
		{
			name:           "name with slashes (invalid)",
			packageName:    "ven/name/component",
			packageVersion: "1.0.1",
			expected:       "pkg:composer/ven/name-component@1.0.1",
		},
		{
			name:           "unknown vendor",
			packageName:    "name",
			packageVersion: "1.0.1",
			expected:       "pkg:composer/name@1.0.1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURLFromComposer(test.packageName, test.packageVersion)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func Test_packageURLFromPear(t *testing.T) {
	tests := []struct {
		name     string
		channel  string
		version  string
		expected string
	}{
		{
			name:     "memcached",
			channel:  "pear.php.net",
			version:  "3.2.0",
			expected: "pkg:pear/pear.php.net/memcached@3.2.0",
		},
		{
			name:     "memcached",
			channel:  "", // important!
			version:  "3.2.0",
			expected: "pkg:pear/pecl.php.net/memcached@3.2.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURLFromPear(test.name, test.channel, test.version)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
