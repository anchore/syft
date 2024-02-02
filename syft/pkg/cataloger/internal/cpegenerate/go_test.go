package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCandidateProductForGo(t *testing.T) {
	tests := []struct {
		pkg      string
		expected string
	}{
		{
			pkg:      "github.com/someone/something",
			expected: "something",
		},
		{
			pkg:      "golang.org/x/xerrors",
			expected: "x/xerrors",
		},
		{
			pkg:      "gopkg.in/yaml.v2",
			expected: "yaml.v2",
		},
		{
			pkg:      "place",
			expected: "",
		},
		{
			pkg:      "place.com/",
			expected: "",
		},
		{
			pkg:      "place.com/someone-or-thing",
			expected: "",
		},
		{
			pkg:      "google.golang.org/genproto/googleapis/rpc/status",
			expected: "genproto",
		},
		{
			pkg:      "github.com/someone/something/long/package/name",
			expected: "something/long/package/name",
		},
		{
			pkg:      "",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.pkg, func(t *testing.T) {
			assert.Equal(t, test.expected, candidateProductForGo(test.pkg))
		})
	}
}

func TestCandidateVendorForGo(t *testing.T) {
	tests := []struct {
		pkg      string
		expected string
	}{
		{
			pkg:      "github.com/someone/something",
			expected: "someone",
		},
		{
			pkg:      "golang.org/x/xerrors",
			expected: "golang",
		},
		{
			pkg:      "gopkg.in/yaml.v2",
			expected: "",
		},
		{
			pkg:      "place",
			expected: "",
		},
		{
			pkg:      "place.com/",
			expected: "",
		},
		{
			pkg:      "place.com/someone-or-thing",
			expected: "",
		},
		{
			pkg:      "google.golang.org/genproto/googleapis/rpc/status",
			expected: "google",
		},
		{
			pkg:      "github.com/someone/something/long/package/name",
			expected: "someone",
		},
	}

	for _, test := range tests {
		t.Run(test.pkg, func(t *testing.T) {
			assert.Equal(t, test.expected, candidateVendorForGo(test.pkg))
		})
	}
}
