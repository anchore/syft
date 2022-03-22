package source

import (
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/syft/file"
	"github.com/bmatcuk/doublestar/v4"
)

var _ FileResolver = (*MockResolver)(nil)

// MockResolver implements the FileResolver interface and is intended for use *only in test code*.
// It provides an implementation that can resolve local filesystem paths using only a provided discrete list of file
// paths, which are typically paths to test fixtures.
type MockResolver struct {
	locations     []file.Location
	metadata      map[file.Location]file.Metadata
	mimeTypeIndex map[string][]file.Location
}

// NewMockResolverForPaths creates a new MockResolver, where the only resolvable
// files are those specified by the supplied paths.
func NewMockResolverForPaths(paths ...string) *MockResolver {
	var locations []file.Location
	for _, p := range paths {
		locations = append(locations, file.NewLocation(p))
	}

	return &MockResolver{
		locations: locations,
		metadata:  make(map[file.Location]file.Metadata),
	}
}

func NewMockResolverForPathsWithMetadata(metadata map[file.Location]file.Metadata) *MockResolver {
	var locations []file.Location
	var mimeTypeIndex = make(map[string][]file.Location)
	for l, m := range metadata {
		locations = append(locations, l)
		mimeTypeIndex[m.MIMEType] = append(mimeTypeIndex[m.MIMEType], l)
	}

	return &MockResolver{
		locations:     locations,
		metadata:      metadata,
		mimeTypeIndex: mimeTypeIndex,
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
func (r MockResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	for _, l := range r.locations {
		if l == location {
			return os.Open(location.RealPath)
		}
	}

	return nil, fmt.Errorf("no file for location: %v", location)
}

// FilesByPath returns all Locations that match the given paths.
func (r MockResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var results []file.Location
	for _, p := range paths {
		for _, location := range r.locations {
			if p == location.RealPath {
				results = append(results, file.NewLocation(p))
			}
		}
	}

	return results, nil
}

// FilesByGlob returns all Locations that match the given path glob pattern.
func (r MockResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var results []file.Location
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
func (r MockResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	paths, err := r.FilesByPath(path)
	if err != nil {
		return nil
	}

	if len(paths) < 1 {
		return nil
	}

	return &paths[0]
}

func (r MockResolver) AllLocations() <-chan file.Location {
	results := make(chan file.Location)
	go func() {
		defer close(results)
		for _, l := range r.locations {
			results <- l
		}
	}()
	return results
}

func (r MockResolver) FileMetadataByLocation(l file.Location) (file.Metadata, error) {
	info, err := os.Stat(l.RealPath)
	if err != nil {
		return file.Metadata{}, err
	}

	// other types not supported
	ty := file.RegularFile
	if info.IsDir() {
		ty = file.Directory
	}

	return file.Metadata{
		Mode:    info.Mode(),
		Type:    ty,
		UserID:  0, // not supported
		GroupID: 0, // not supported
		Size:    info.Size(),
	}, nil
}

func (r MockResolver) FilesByMIMEType(types ...string) ([]file.Location, error) {
	var locations []file.Location
	for _, ty := range types {
		locations = append(r.mimeTypeIndex[ty], locations...)
	}
	return locations, nil
}
