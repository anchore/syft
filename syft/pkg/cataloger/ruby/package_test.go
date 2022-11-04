package ruby

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "p",
			version:  "v",
			expected: "pkg:gem/p@v",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s@%s", test.name, test.version), func(t *testing.T) {
			actual := packageURL(test.name, test.version)
			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected packageURL (-want +got):\n%s", diff)
			}
		})
	}
}
