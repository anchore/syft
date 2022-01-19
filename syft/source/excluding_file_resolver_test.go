package source

import (
	"io"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"

	"github.com/stretchr/testify/assert"
)

func TestExcludingResolver(t *testing.T) {

	tests := []struct {
		name      string
		locations []string
		excludeFn excludeFn
		expected  []string
	}{
		{
			name:      "keeps locations",
			locations: []string{"a", "b", "c"},
			excludeFn: func(s string) bool {
				return false
			},
			expected: []string{"a", "b", "c"},
		},
		{
			name:      "removes locations",
			locations: []string{"d", "e", "f"},
			excludeFn: func(s string) bool {
				return true
			},
			expected: []string{},
		},
		{
			name:      "removes first match",
			locations: []string{"g", "h", "i"},
			excludeFn: func(s string) bool {
				return s == "g"
			},
			expected: []string{"h", "i"},
		},
		{
			name:      "removes last match",
			locations: []string{"j", "k", "l"},
			excludeFn: func(s string) bool {
				return s == "l"
			},
			expected: []string{"j", "k"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &mockResolver{
				locations: test.locations,
			}
			excludingResolver := NewExcludingResolver(resolver, test.excludeFn)

			locations, _ := excludingResolver.FilesByPath()
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			locations, _ = excludingResolver.FilesByGlob()
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			locations, _ = excludingResolver.FilesByMIMEType()
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			locations = []Location{}

			channel := excludingResolver.AllLocations()
			for location := range channel {
				locations = append(locations, location)
			}
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			diff := difference(test.locations, test.expected)

			for _, path := range diff {
				assert.False(t, excludingResolver.HasPath(path))
				c, err := excludingResolver.FileContentsByLocation(makeLocation(path))
				assert.Nil(t, c)
				assert.Error(t, err)
				m, err := excludingResolver.FileMetadataByLocation(makeLocation(path))
				assert.Empty(t, m.LinkDestination)
				assert.Error(t, err)
				l := excludingResolver.RelativeFileByPath(makeLocation(""), path)
				assert.Nil(t, l)
			}

			for _, path := range test.expected {
				assert.True(t, excludingResolver.HasPath(path))
				c, err := excludingResolver.FileContentsByLocation(makeLocation(path))
				assert.NotNil(t, c)
				assert.Nil(t, err)
				m, err := excludingResolver.FileMetadataByLocation(makeLocation(path))
				assert.NotEmpty(t, m.LinkDestination)
				assert.Nil(t, err)
				l := excludingResolver.RelativeFileByPath(makeLocation(""), path)
				assert.NotNil(t, l)
			}
		})
	}
}

// difference returns the elements in `a` that aren't in `b`.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func makeLocation(path string) Location {
	return Location{
		Coordinates: Coordinates{
			RealPath:     path,
			FileSystemID: "",
		},
		VirtualPath: "",
		ref:         file.Reference{},
	}
}

func locationPaths(locations []Location) []string {
	paths := []string{}
	for _, l := range locations {
		paths = append(paths, l.RealPath)
	}
	return paths
}

type mockResolver struct {
	locations []string
}

func (r *mockResolver) getLocations() ([]Location, error) {
	out := []Location{}
	for _, path := range r.locations {
		out = append(out, makeLocation(path))
	}
	return out, nil
}

func (r *mockResolver) FileContentsByLocation(_ Location) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("Hello, world!")), nil
}

func (r *mockResolver) FileMetadataByLocation(_ Location) (FileMetadata, error) {
	return FileMetadata{
		LinkDestination: "MOCK",
	}, nil
}

func (r *mockResolver) HasPath(_ string) bool {
	return true
}

func (r *mockResolver) FilesByPath(_ ...string) ([]Location, error) {
	return r.getLocations()
}

func (r *mockResolver) FilesByGlob(_ ...string) ([]Location, error) {
	return r.getLocations()
}

func (r *mockResolver) FilesByMIMEType(_ ...string) ([]Location, error) {
	return r.getLocations()
}

func (r *mockResolver) RelativeFileByPath(_ Location, path string) *Location {
	return &Location{
		Coordinates: Coordinates{
			RealPath: path,
		},
	}
}

func (r *mockResolver) AllLocations() <-chan Location {
	c := make(chan Location)
	go func() {
		defer close(c)
		locations, _ := r.getLocations()
		for _, location := range locations {
			c <- location
		}
	}()
	return c
}
