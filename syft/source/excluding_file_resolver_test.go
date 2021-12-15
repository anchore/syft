package source

import (
	"github.com/anchore/stereoscope/pkg/file"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExcludingResolver(t *testing.T) {

	tests := []struct {
		name           string
		locations      []string
		excludeFn      func(string, os.FileInfo) bool
		expectedLength int
	}{
		{
			name:      "keeps locations",
			locations: []string{"a", "b", "c"},
			excludeFn: func(s string, info os.FileInfo) bool {
				return false
			},
			expectedLength: 3,
		},
		{
			name:      "removes locations",
			locations: []string{"d", "e", "f"},
			excludeFn: func(s string, info os.FileInfo) bool {
				return true
			},
			expectedLength: 0,
		},
		{
			name:      "removes first match",
			locations: []string{"g", "h", "i"},
			excludeFn: func(s string, info os.FileInfo) bool {
				return s == "g"
			},
			expectedLength: 2,
		},
		{
			name:      "removes last match",
			locations: []string{"j", "k", "l"},
			excludeFn: func(s string, info os.FileInfo) bool {
				return s == "l"
			},
			expectedLength: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &mockResolver{
				locations: test.locations,
			}
			excludingResolver := NewExcludingResolver(resolver, test.excludeFn)

			fc, _ := excludingResolver.FilesByPath()
			assert.Equal(t, test.expectedLength, len(fc))

			fc, _ = excludingResolver.FilesByGlob()
			assert.Equal(t, test.expectedLength, len(fc))

			fc, _ = excludingResolver.FilesByMIMEType()
			assert.Equal(t, test.expectedLength, len(fc))
		})
	}
}

type mockResolver struct {
	locations []string
}

func (r *mockResolver) getLocations() ([]Location, error) {
	out := []Location{}
	for _, l := range r.locations {
		out = append(out, Location{
			Coordinates: Coordinates{
				RealPath:     l,
				FileSystemID: "",
			},
			VirtualPath: l,
			ref:         file.Reference{},
		})
	}
	return out, nil
}

func (r *mockResolver) FileContentsByLocation(_ Location) (io.ReadCloser, error) {
	return nil, nil
}

func (r *mockResolver) FileMetadataByLocation(_ Location) (FileMetadata, error) {
	return FileMetadata{}, nil
}

func (r *mockResolver) HasPath(_ string) bool {
	return false
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

func (r *mockResolver) RelativeFileByPath(_ Location, _ string) *Location {
	return &Location{}
}

func (r *mockResolver) AllLocations() <-chan Location {
	return nil
}
