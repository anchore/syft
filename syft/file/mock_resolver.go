package file

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/anchore/stereoscope/pkg/file"
)

var _ Resolver = (*MockResolver)(nil)

// MockResolver implements the FileResolver interface and is intended for use *only in test code*.
// It provides an implementation that can resolve local filesystem paths using only a provided discrete list of file
// paths, which are typically paths to test fixtures.
type MockResolver struct {
	locations     []Location
	metadata      map[Coordinates]Metadata
	mimeTypeIndex map[string][]Location
	extension     map[string][]Location
	basename      map[string][]Location
}

// NewMockResolverForPaths creates a new MockResolver, where the only resolvable
// files are those specified by the supplied paths.
func NewMockResolverForPaths(paths ...string) *MockResolver {
	var locations []Location
	extension := make(map[string][]Location)
	basename := make(map[string][]Location)
	for _, p := range paths {
		loc := NewLocation(p)
		locations = append(locations, loc)
		ext := path.Ext(p)
		extension[ext] = append(extension[ext], loc)
		bn := path.Base(p)
		basename[bn] = append(basename[bn], loc)
	}

	return &MockResolver{
		locations: locations,
		metadata:  make(map[Coordinates]Metadata),
		extension: extension,
		basename:  basename,
	}
}

func NewMockResolverForPathsWithMetadata(metadata map[Coordinates]Metadata) *MockResolver {
	var locations []Location
	var mimeTypeIndex = make(map[string][]Location)
	extension := make(map[string][]Location)
	basename := make(map[string][]Location)
	for c, m := range metadata {
		l := NewLocationFromCoordinates(c)
		locations = append(locations, l)
		mimeTypeIndex[m.MIMEType] = append(mimeTypeIndex[m.MIMEType], l)
		ext := path.Ext(l.RealPath)
		extension[ext] = append(extension[ext], l)
		bn := path.Base(l.RealPath)
		basename[bn] = append(basename[bn], l)
	}

	return &MockResolver{
		locations:     locations,
		metadata:      metadata,
		mimeTypeIndex: mimeTypeIndex,
		extension:     extension,
		basename:      basename,
	}
}

// HasPath indicates if the given path exists in the underlying source.
func (r MockResolver) HasPath(path string) bool {
	for _, l := range r.locations {
		if l.RealPath == path {
			return true
		}
	}
	return false
}

// String returns the string representation of the MockResolver.
func (r MockResolver) String() string {
	return fmt.Sprintf("mock:(%s,...)", r.locations[0].RealPath)
}

// FileContentsByLocation fetches file contents for a single location. If the
// path does not exist, an error is returned.
func (r MockResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	for _, l := range r.locations {
		if l.Coordinates == location.Coordinates {
			return os.Open(location.RealPath)
		}
	}

	return nil, fmt.Errorf("no file for location: %v", location)
}

// FilesByPath returns all Locations that match the given paths.
func (r MockResolver) FilesByPath(paths ...string) ([]Location, error) {
	var results []Location
	for _, p := range paths {
		for _, location := range r.locations {
			if p == location.RealPath {
				results = append(results, NewLocation(p))
			}
		}
	}

	return results, nil
}

// FilesByGlob returns all Locations that match the given path glob pattern.
func (r MockResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	var results []Location
	for _, pattern := range patterns {
		for _, location := range r.locations {
			matches, err := doublestar.Match(pattern, location.RealPath)
			if err != nil {
				return nil, err
			}
			if matches {
				results = append(results, location)
			}
		}
	}

	return results, nil
}

// RelativeFileByPath returns a single Location for the given path.
func (r MockResolver) RelativeFileByPath(_ Location, path string) *Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}

	if len(paths) < 1 {
		return nil
	}

	return &paths[0]
}

func (r MockResolver) AllLocations(ctx context.Context) <-chan Location {
	results := make(chan Location)
	go func() {
		defer close(results)
		for _, l := range r.locations {
			select {
			case <-ctx.Done():
				return
			case results <- l:
				continue
			}
		}
	}()
	return results
}

func (r MockResolver) FileMetadataByLocation(l Location) (Metadata, error) {
	info, err := os.Stat(l.RealPath)
	if err != nil {
		return Metadata{}, err
	}

	// other types not supported
	ty := file.TypeRegular
	if info.IsDir() {
		ty = file.TypeDirectory
	}

	return Metadata{
		FileInfo: info,
		Type:     ty,
		UserID:   0, // not supported
		GroupID:  0, // not supported
	}, nil
}

func (r MockResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	var locations []Location
	for _, ty := range types {
		locations = append(r.mimeTypeIndex[ty], locations...)
	}
	return locations, nil
}

func (r MockResolver) FilesByExtension(extensions ...string) ([]Location, error) {
	var results []Location
	for _, ext := range extensions {
		results = append(results, r.extension[ext]...)
	}
	return results, nil
}

func (r MockResolver) FilesByBasename(filenames ...string) ([]Location, error) {
	var results []Location
	for _, filename := range filenames {
		results = append(results, r.basename[filename]...)
	}
	return results, nil
}

func (r MockResolver) FilesByBasenameGlob(_ ...string) ([]Location, error) {
	// TODO implement me
	panic("implement me")
}

func (r MockResolver) Write(_ Location, _ io.Reader) error {
	return nil
}
