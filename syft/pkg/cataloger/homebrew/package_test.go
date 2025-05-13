package homebrew

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name           string
		packageName    string
		packageVersion string
		expected       string
	}{
		// preemptive based on https://github.com/package-url/purl-spec/pull/281
		{
			name:           "standard homebrew package URL",
			packageName:    "foo",
			packageVersion: "1.2.3",
			expected:       "pkg:brew/foo@1.2.3",
		},
		{
			name:           "another example",
			packageName:    "bar",
			packageVersion: "9.8.7",
			expected:       "pkg:brew/bar@9.8.7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(test.packageName, test.packageVersion)
			assert.Equal(t, test.expected, actual, "expected package URL to match")
		})
	}
}
