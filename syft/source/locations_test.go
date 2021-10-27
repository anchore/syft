package source

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocationsSort(t *testing.T) {

	etcHosts := Location{
		RealPath:     "/etc/hosts",
		VirtualPath:  "",
		FileSystemID: "a",
	}

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

	etcConfig := Location{
		RealPath:     "/etc/config",
		VirtualPath:  "",
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
			name: "by real path",
			input: []Location{
				etcHosts, binA, etcConfig,
			},
			expected: []Location{
				binA, etcConfig, etcHosts,
			},
		},
		{
			name: "by filesystem",
			input: []Location{
				binB, binA,
			},
			expected: []Location{
				binA, binB,
			},
		},
		{
			name: "by virtual path",
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
			sort.Sort(Locations(test.input))
			assert.Equal(t, test.expected, test.input)
		})
	}
}
