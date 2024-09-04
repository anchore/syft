package options

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_networkEnabled(t *testing.T) {
	tests := []struct {
		directives string
		test       string
		expected   *bool
	}{
		{
			directives: "",
			test:       "java",
			expected:   nil,
		},
		{
			directives: "none",
			test:       "java",
			expected:   ptr(false),
		},
		{
			directives: "none,+java",
			test:       "java",
			expected:   ptr(true),
		},
		{
			directives: "all",
			test:       "java",
			expected:   ptr(true),
		},
		{
			directives: "on",
			test:       "java",
			expected:   ptr(true),
		},
		{
			directives: "on,-java",
			test:       "java",
			expected:   ptr(false),
		},
	}

	for _, test := range tests {
		t.Run(test.directives, func(t *testing.T) {
			n := Network{
				Directives: []string{test.directives},
			}
			require.NoError(t, n.PostLoad())

			got := n.Enabled(test.test)
			require.Equal(t, test.expected, got)
		})
	}
}
