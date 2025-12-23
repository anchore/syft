package ocimodelsource

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ociModelResolver)(nil)

// ociModelResolver is a file.Resolver implementation that provides access to
// GGUF header data fetched from OCI model artifacts via range-GET requests.
type ociModelResolver struct {
	tempDir    string                   // temp directory containing all layer files
	layerFiles map[string]layerInfo     // digest -> layer info (temp path + media type)
	locations  map[string]file.Location // digest -> location
}

// newOCIModelResolver creates a new resolver with the given temp directory and layer files.
func newOCIModelResolver(tempDir string, layerFiles map[string]layerInfo) *ociModelResolver {
	// Create locations for all layer files
	// Each location has RealPath="/", FileSystemID=digest, AccessPath="/"
	locations := make(map[string]file.Location, len(layerFiles))
	for digest := range layerFiles {
		// Use NewVirtualLocationFromCoordinates with digest as FileSystemID
		coords := file.NewCoordinates("/", digest)
		locations[digest] = file.NewVirtualLocationFromCoordinates(coords, "/")
	}

	return &ociModelResolver{
		tempDir:    tempDir,
		layerFiles: layerFiles,
		locations:  locations,
	}
}

// FilesByMediaType returns locations for layers matching the given media type patterns.
// Patterns support glob-style matching (e.g., "application/vnd.docker.ai*").
func (r *ociModelResolver) FilesByMediaType(types ...string) ([]file.Location, error) {
	var matches []file.Location

	for digest, info := range r.layerFiles {
		for _, pattern := range types {
			matched, err := filepath.Match(pattern, info.MediaType)
			if err != nil {
				return nil, fmt.Errorf("invalid media type pattern %q: %w", pattern, err)
			}
			if matched {
				if loc, ok := r.locations[digest]; ok {
					matches = append(matches, loc)
				}
				break // Don't add the same location twice
			}
		}
	}

	return matches, nil
}

// FileContentsByLocation returns the contents of the file at the given location.
// The location's FileSystemID contains the layer digest, which is used to look up the temp file.
// This method is used as part of the content selection in the generic cataloger when locations
// are returned by searching for contents by media type.
func (r *ociModelResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	// Look up the temp file path using the digest stored in FileSystemID
	digest := location.FileSystemID
	info, ok := r.layerFiles[digest]
	if !ok {
		return nil, fmt.Errorf("no file found for digest %q", digest)
	}
	return os.Open(info.TempPath)
}

// FileMetadataByLocation returns metadata for the file at the given location.
func (r *ociModelResolver) FileMetadataByLocation(_ file.Location) (m file.Metadata, err error) {
	return m, nil
}

// HasPath checks if the given path exists in the resolver.
func (r *ociModelResolver) HasPath(path string) bool {
	// The virtual path is "/" for all files
	if path == "/" && len(r.layerFiles) > 0 {
		return true
	}
	return false
}

// FilesByPath returns locations for files matching the given paths.
func (r *ociModelResolver) FilesByPath(_ ...string) ([]file.Location, error) {
	return nil, nil
}

// FilesByGlob returns locations for files matching the given glob patterns.
func (r *ociModelResolver) FilesByGlob(_ ...string) ([]file.Location, error) {
	return nil, nil
}

// FilesByMIMEType returns locations for files with the given MIME types.
// This is not implemented for OCI model artifacts as we don't have MIME type detection.
func (r *ociModelResolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	// Not implemented - OCI model artifacts don't have MIME type detection
	return nil, nil
}

// RelativeFileByPath returns a file at the given path relative to the reference location.
// This is not applicable for OCI model artifacts.
func (r *ociModelResolver) RelativeFileByPath(_ file.Location, _ string) *file.Location {
	// Not implemented - no layer hierarchy in OCI model artifacts
	return nil
}

// AllLocations returns all file locations in the resolver.
func (r *ociModelResolver) AllLocations(ctx context.Context) <-chan file.Location {
	ch := make(chan file.Location)

	go func() {
		defer close(ch)

		for _, loc := range r.locations {
			select {
			case <-ctx.Done():
				return
			case ch <- loc:
			}
		}
	}()

	return ch
}

// cleanup removes the temp directory and all files within it.
func (r *ociModelResolver) cleanup() error {
	if r.tempDir == "" {
		return nil
	}
	return os.RemoveAll(r.tempDir)
}
