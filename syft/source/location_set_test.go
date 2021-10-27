package source

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocationSet(t *testing.T) {

	etcHostsLinkVar := Location{
		RealPath:     "/etc/hosts",
		VirtualPath:  "/var/etc/hosts",
		FileSystemID: "a",
	}

	etcHostsLinkHome := Location{
		RealPath:     "/etc/hosts",
		VirtualPath:  "/home/wagoodman/hosts",
		FileSystemID: "a",
	}

	binA := Location{
		RealPath:     "/bin",
		VirtualPath:  "/usr/bin",
		FileSystemID: "a",
	}

	binB := Location{
		RealPath:     "/bin",
		VirtualPath:  "/usr/bin",
		FileSystemID: "b",
	}

	tests := []struct {
		name     string
		input    []Location
		expected []Location
	}{
		{
			name: "de-dup same location",
			input: []Location{
				binA, binA, binA,
			},
			expected: []Location{
				binA,
			},
		},
		{
			name: "dont de-dup different filesystem",
			input: []Location{
				binB, binA,
			},
			expected: []Location{
				binA, binB,
			},
		},
		{
			name: "dont de-dup different virtual paths",
			input: []Location{
				etcHostsLinkVar, etcHostsLinkHome,
			},
			expected: []Location{
				etcHostsLinkHome, etcHostsLinkVar,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, NewLocationSet(test.input...).ToSlice())
		})
	}
}
