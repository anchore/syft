package source

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocationSet(t *testing.T) {

	etcHostsLinkVar := Location{
		Coordinates: Coordinates{
			RealPath:     "/etc/hosts",
			FileSystemID: "a",
		},
		VirtualPath: "/var/etc/hosts",
	}

	etcHostsLinkHome := Location{
		Coordinates: Coordinates{
			RealPath:     "/etc/hosts",
			FileSystemID: "a",
		},
		VirtualPath: "/home/wagoodman/hosts",
	}

	binA := Location{
		Coordinates: Coordinates{
			RealPath:     "/bin",
			FileSystemID: "a",
		},
		VirtualPath: "/usr/bin",
	}

	binB := Location{
		Coordinates: Coordinates{
			RealPath:     "/bin",
			FileSystemID: "b",
		},
		VirtualPath: "/usr/bin",
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
			set := NewLocationSet(test.input...)
			assert.Equal(t, test.expected, set.ToSlice())
		})
	}
}

func TestLocationSet_Hash(t *testing.T) {
	etcAlink := Location{
		Coordinates: Coordinates{
			RealPath:     "/etc/hosts",
			FileSystemID: "a",
		},
		VirtualPath: "/var/etc/hosts",
	}

	etcA := Location{
		Coordinates: Coordinates{
			RealPath:     "/etc/hosts",
			FileSystemID: "a",
		},
	}

	etcB := Location{
		Coordinates: Coordinates{
			RealPath:     "/etc/hosts",
			FileSystemID: "b",
		},
	}

	binA := Location{
		Coordinates: Coordinates{
			RealPath:     "/bin",
			FileSystemID: "a",
		},
		VirtualPath: "/usr/bin",
	}

	binB := Location{
		Coordinates: Coordinates{
			RealPath:     "/bin",
			FileSystemID: "b",
		},
		VirtualPath: "/usr/bin",
	}

	tests := []struct {
		name string
		setA LocationSet
		setB LocationSet
		want assert.ComparisonAssertionFunc
	}{
		{
			name: "empty sets have the same hash",
			setA: NewLocationSet(),
			setB: NewLocationSet(),
			want: assert.Equal,
		},
		{
			name: "sets with same elements accessed through different paths have the same hash",
			setA: NewLocationSet(binA, etcA),
			setB: NewLocationSet(etcAlink, binA),
			want: assert.Equal,
		},
		{
			name: "sets with same elements have the same hash",
			setA: NewLocationSet(binA, etcA),
			setB: NewLocationSet(etcA, binA),
			want: assert.Equal,
		},
		{
			name: "sets with different element counts have different hashes",
			setA: NewLocationSet(binA, etcA),
			setB: NewLocationSet(binA),
			want: assert.NotEqual,
		},
		{
			name: "sets with same path but different FS IDs have the same hash",
			setA: NewLocationSet(binA),
			setB: NewLocationSet(binB),
			want: assert.Equal,
		},
		{
			name: "sets with same paths but different FS IDs have the same hash",
			setA: NewLocationSet(etcA, binA),
			setB: NewLocationSet(binB, etcB),
			want: assert.Equal,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA, err := artifact.IDByHash(tt.setA)
			require.NoError(t, err)
			gotB, err := artifact.IDByHash(tt.setB)
			require.NoError(t, err)
			tt.want(t, gotA, gotB)
		})
	}
}
