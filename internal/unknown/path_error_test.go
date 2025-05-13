package unknown

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_ProcessPathErrors(t *testing.T) {
	tests := []struct {
		errorText string
		expected  error
	}{
		{
			errorText: `prefix path="/var/lib/thing" suffix`,
			expected: &CoordinateError{
				Coordinates: file.Coordinates{
					RealPath: "/var/lib/thing",
				},
				Reason: fmt.Errorf(`prefix path="/var/lib/thing" suffix`),
			},
		},
		{
			errorText: `prefix path="/var/lib/thing"`,
			expected: &CoordinateError{
				Coordinates: file.Coordinates{
					RealPath: "/var/lib/thing",
				},
				Reason: fmt.Errorf(`prefix path="/var/lib/thing"`),
			},
		},
		{
			errorText: `path="/var/lib/thing" suffix`,
			expected: &CoordinateError{
				Coordinates: file.Coordinates{
					RealPath: "/var/lib/thing",
				},
				Reason: fmt.Errorf(`path="/var/lib/thing" suffix`),
			},
		},
		{
			errorText: "all your base are belong to us",
			expected:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.errorText, func(t *testing.T) {
			got := ProcessPathErrors(fmt.Errorf("%s", test.errorText))
			require.Equal(t, test.expected, got)
		})
	}
}
