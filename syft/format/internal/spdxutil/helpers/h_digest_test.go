package helpers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_HDigestToSHA(t *testing.T) {
	tests := []struct {
		name     string
		hDigest  string
		expected string
		error    bool
	}{
		{
			name:     "valid h1digest",
			hDigest:  "h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=",
			expected: "sha256:f10a9c0e0ceb52a9546ff1b63d04d68ae786a33b91d7cf3881d74ccb093a88b5",
			error:    false,
		},
		{
			name:     "other valid h1digest",
			hDigest:  "h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=",
			expected: "sha256:4933fc0ef0f273f748e5bf13e61b21b648d2f84e364e7cac34250f7637221a16",
			error:    false,
		},
		{
			name:     "invalid h1digest",
			hDigest:  "h12:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=",
			expected: "",
			error:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			algo, digest, err := HDigestToSHA(test.hDigest)
			if test.error {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}
			got := fmt.Sprintf("%s:%s", algo, digest)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_HDigestFromSHA(t *testing.T) {
	tests := []struct {
		name     string
		sha      string
		expected string
		error    bool
	}{
		{
			name:     "valid sha",
			sha:      "sha256:f10a9c0e0ceb52a9546ff1b63d04d68ae786a33b91d7cf3881d74ccb093a88b5",
			expected: "h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=",
			error:    false,
		},
		{
			name:     "other valid sha",
			sha:      "sha256:4933fc0ef0f273f748e5bf13e61b21b648d2f84e364e7cac34250f7637221a16",
			expected: "h1:STP8DvDyc/dI5b8T5hshtkjS+E42TnysNCUPdjciGhY=",
			error:    false,
		},
		{
			name:     "invalid sha",
			expected: "h12:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=",
			sha:      "sha256:f10a9c0e0zzzzceb52a99968ae786a33b91d7cf3881d74ccb093a88b5",
			error:    true,
		},
		{
			name:     "invalid algorithm",
			expected: "h12:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=",
			sha:      "sha1:f10a9c0e0ceb52a9546ff1b63d04d68ae786a33b91d7cf3881d74ccb093a88b5",
			error:    true,
		},
		{
			name:     "empty sha",
			expected: "",
			sha:      "sha256:",
			error:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parts := strings.Split(test.sha, ":")
			algo := parts[0]
			digest := parts[1]
			got, err := HDigestFromSHA(algo, digest)
			if test.error {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, test.expected, got)
		})
	}
}
