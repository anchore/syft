package file

import (
	"sort"
	"sync"
	"testing"

	"github.com/gohugoio/hashstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/evidence"
	"github.com/anchore/syft/syft/artifact"
)

func TestLocationSet_SortPaths(t *testing.T) {

	etcHostsLinkVar := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "a",
			},
			AccessPath: "/var/etc/hosts",
		},
	}

	etcHostsLinkHome := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "a",
			},
			AccessPath: "/home/wagoodman/hosts",
		},
	}

	binA := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/bin",
				FileSystemID: "a",
			},
			AccessPath: "/usr/bin",
		},
	}

	binB := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/bin",
				FileSystemID: "b",
			},
			AccessPath: "/usr/bin",
		},
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
			actual := NewLocationSet(test.input...).ToSlice()
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestLocationSet_SortEvidence(t *testing.T) {
	primaryEvidence := map[string]string{evidence.AnnotationKey: evidence.PrimaryAnnotation}
	secondaryEvidence := map[string]string{evidence.AnnotationKey: evidence.SupportingAnnotation}

	binPrimary := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/bin",
				FileSystemID: "a",
			},
			AccessPath: "/usr/bin",
		},
		LocationMetadata: LocationMetadata{
			Annotations: primaryEvidence,
		},
	}

	binSecondary := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/bin",
				FileSystemID: "a",
			},
			AccessPath: "/usr/bin",
		},
		LocationMetadata: LocationMetadata{
			Annotations: secondaryEvidence,
		},
	}

	binNoEvidence := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/bin",
				FileSystemID: "a",
			},
			AccessPath: "/usr/bin",
		},
	}

	etcHostsPrimary := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "a",
			},
			AccessPath: "/var/etc/hosts",
		},
		LocationMetadata: LocationMetadata{
			Annotations: primaryEvidence,
		},
	}

	etcHostsSecondary := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "a",
			},
			AccessPath: "/var/etc/hosts",
		},
		LocationMetadata: LocationMetadata{
			Annotations: secondaryEvidence,
		},
	}

	etcHostsNoEvidence := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "a",
			},
			AccessPath: "/var/etc/hosts",
		},
	}

	tests := []struct {
		name     string
		input    []Location
		expected []Location
	}{
		{
			name: "sort primary, secondary, tertiary, no evidence",
			input: []Location{
				binNoEvidence, binPrimary, binSecondary,
			},
			expected: []Location{
				binPrimary, binSecondary, binNoEvidence,
			},
		},
		{
			name: "sort by evidence, then path",
			input: []Location{
				etcHostsNoEvidence, etcHostsSecondary,
				binSecondary, binNoEvidence,
				binPrimary, etcHostsPrimary,
			},
			expected: []Location{
				binPrimary, etcHostsPrimary, binSecondary, etcHostsSecondary, binNoEvidence, etcHostsNoEvidence,
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

func TestLocationSet_Hash(t *testing.T) {
	etcAlink := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "a",
			},
			AccessPath: "/var/etc/hosts",
		},
	}

	etcA := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "a",
			},
		},
	}

	etcB := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/etc/hosts",
				FileSystemID: "b",
			},
		},
	}

	binA := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/bin",
				FileSystemID: "a",
			},
			AccessPath: "/usr/bin",
		},
	}

	binB := Location{
		LocationData: LocationData{
			Coordinates: Coordinates{
				RealPath:     "/bin",
				FileSystemID: "b",
			},
			AccessPath: "/usr/bin",
		},
	}

	inA := NewLocationFromCoordinates(Coordinates{RealPath: "/app.war", FullPath: "/app.war!/a.jar!/package.json"})
	inB := NewLocationFromCoordinates(Coordinates{RealPath: "/app.war", FullPath: "/app.war!/b.jar!/package.json"})
	etcFull := Location{LocationData: LocationData{Coordinates: Coordinates{RealPath: "/etc/hosts", FileSystemID: "a", FullPath: "/etc/hosts"}}}

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
		{
			name: "same outer archive but different nested entries have different hashes",
			setA: NewLocationSet(inA),
			setB: NewLocationSet(inB),
			want: assert.NotEqual,
		},
		{
			name: "a full path equal to the real path has the same hash as a blank one",
			setA: NewLocationSet(etcA),
			setB: NewLocationSet(etcFull),
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

// IDs outside archives must not change from when only real paths were hashed
func TestLocationSet_Hash_unchangedOutsideArchives(t *testing.T) {
	want, err := hashstructure.Hash([]string{"/etc/hosts", "/bin"}, &hashstructure.HashOptions{ZeroNil: true, SlicesAsSets: true})
	require.NoError(t, err)

	got, err := NewLocationSet(NewLocation("/etc/hosts"), NewVirtualLocation("/bin", "/usr/bin")).Hash()
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestLocationSet_Add_DoesNotMutateCallerAnnotations(t *testing.T) {
	first := NewLocation("/var/lib/dpkg/status").WithAnnotation("evidence", "primary")
	second := NewLocation("/var/lib/dpkg/status").WithAnnotation("visible", "true")

	s := NewLocationSet(first)
	s.Add(second)

	assert.Equal(t, map[string]string{"evidence": "primary"}, first.Annotations)
	assert.Equal(t, map[string]string{"visible": "true"}, second.Annotations)
	assert.Equal(t, map[string]string{"evidence": "primary", "visible": "true"}, s.ToSlice()[0].Annotations)
}

func TestLocationSet_Add_DoesNotAliasCallerAnnotationsOnInsert(t *testing.T) {
	loc := NewLocation("/a").WithAnnotation("evidence", "primary")

	s := NewLocationSet(loc)
	s.ToSlice()[0].Annotations["visible"] = "true"

	assert.Equal(t, map[string]string{"evidence": "primary"}, loc.Annotations)
}

func TestLocationSet_Add_MergesIntoNilAnnotations(t *testing.T) {
	s := NewLocationSet(Location{LocationData: LocationData{Coordinates: Coordinates{RealPath: "/a"}, AccessPath: "/a"}})

	s.Add(NewLocation("/a").WithAnnotation("evidence", "primary"))

	assert.Equal(t, map[string]string{"evidence": "primary"}, s.ToSlice()[0].Annotations)
}

func TestLocationSet_Add_SharedLocationAcrossGoroutines(t *testing.T) {
	// mirrors catalogers that hand one annotated location to every package parsed in parallel;
	// no assertions, it fails only under -race (on in CI, or RACE=true locally)
	shared := NewLocation("/var/lib/dpkg/status").WithAnnotation("evidence", "primary")

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			for range 100 {
				s := NewLocationSet(shared)
				s.Add(shared)
			}
		})
	}
	wg.Wait()
}
