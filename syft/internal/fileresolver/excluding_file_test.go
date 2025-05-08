package fileresolver

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
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
			er := NewExcludingDecorator(resolver, test.excludeFn)

			locations, _ := er.FilesByPath()
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			locations, _ = er.FilesByGlob()
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			locations, _ = er.FilesByMIMEType()
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			locations = []file.Location{}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			channel := er.AllLocations(ctx)
			for location := range channel {
				locations = append(locations, location)
			}
			assert.ElementsMatch(t, locationPaths(locations), test.expected)

			diff := difference(test.locations, test.expected)

			for _, path := range diff {
				assert.False(t, er.HasPath(path))
				c, err := er.FileContentsByLocation(file.NewLocation(path))
				assert.Nil(t, c)
				assert.Error(t, err)
				m, err := er.FileMetadataByLocation(file.NewLocation(path))
				assert.Empty(t, m.LinkDestination)
				assert.Error(t, err)
				l := er.RelativeFileByPath(file.NewLocation(""), path)
				assert.Nil(t, l)
			}

			for _, path := range test.expected {
				assert.True(t, er.HasPath(path))
				c, err := er.FileContentsByLocation(file.NewLocation(path))
				assert.NotNil(t, c)
				assert.Nil(t, err)
				m, err := er.FileMetadataByLocation(file.NewLocation(path))
				assert.NotEmpty(t, m.LinkDestination)
				assert.Nil(t, err)
				l := er.RelativeFileByPath(file.NewLocation(""), path)
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

func locationPaths(locations []file.Location) []string {
	paths := []string{}
	for _, l := range locations {
		paths = append(paths, l.RealPath)
	}
	return paths
}

type mockResolver struct {
	locations []string
}

func (r *mockResolver) getLocations() ([]file.Location, error) {
	out := []file.Location{}
	for _, path := range r.locations {
		out = append(out, file.NewLocation(path))
	}
	return out, nil
}

func (r *mockResolver) FileContentsByLocation(_ file.Location) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("Hello, world!")), nil
}

func (r *mockResolver) FileMetadataByLocation(_ file.Location) (file.Metadata, error) {
	return file.Metadata{
		LinkDestination: "MOCK",
	}, nil
}

func (r *mockResolver) HasPath(_ string) bool {
	return true
}

func (r *mockResolver) FilesByPath(_ ...string) ([]file.Location, error) {
	return r.getLocations()
}

func (r *mockResolver) FilesByGlob(_ ...string) ([]file.Location, error) {
	return r.getLocations()
}

func (r *mockResolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	return r.getLocations()
}

func (r *mockResolver) FilesByExtension(_ ...string) ([]file.Location, error) {
	return r.getLocations()
}

func (r *mockResolver) FilesByBasename(_ ...string) ([]file.Location, error) {
	return r.getLocations()
}

func (r *mockResolver) FilesByBasenameGlob(_ ...string) ([]file.Location, error) {
	return r.getLocations()
}

func (r *mockResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	l := file.NewLocation(path)
	return &l
}

func (r *mockResolver) AllLocations(ctx context.Context) <-chan file.Location {
	c := make(chan file.Location)
	go func() {
		defer close(c)
		locations, _ := r.getLocations()
		for _, location := range locations {
			select {
			case <-ctx.Done():
				return
			case c <- location:
				continue
			}
		}
	}()
	return c
}
