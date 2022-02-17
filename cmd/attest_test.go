package cmd

import (
	"testing"

	"github.com/anchore/syft/test/cli"
)

func TestPasswordFunc(t *testing.T) {
	tests := []struct {
		name           string
		shouldReturnPW bool
	}{
		{
			name:           "given an encryted key with no password passFunc returns nil",
			shouldReturnPW: false,
		},
		{
			name:           "given an encryted key with a password passFunc returns pw",
			shouldReturnPW: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cleanup := cli.SetupPKI(t)
			defer cleanup()
			_, err := hasPassword("cosign.key")
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
