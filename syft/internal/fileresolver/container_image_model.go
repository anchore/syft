package fileresolver

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ContainerImageModel)(nil)
var _ file.OCIMediaTypeResolver = (*ContainerImageModel)(nil)

// LayerInfo holds information about an OCI model layer file stored on disk.
type LayerInfo struct {
	TempPath  string // Path to the temp file on disk
	MediaType string // OCI media type of the layer
}

// ContainerImageModel is a file.Resolver implementation that provides access to
// GGUF header data fetched from OCI model artifacts via range-GET requests.
// This does not fetch the entire model from the registry, only a sliver of it.
type ContainerImageModel struct {
	tempDir    string                   // temp directory containing all layer files
	layerFiles map[string]LayerInfo     // digest -> layer info (temp path + media type)
	locations  map[string]file.Location // digest -> location
}

// NewContainerImageModel creates a new resolver with the given temp directory and layer files.
func NewContainerImageModel(tempDir string, layerFiles map[string]LayerInfo) *ContainerImageModel {
	// Create locations for all layer files
	// Each location has RealPath="/", FileSystemID=digest, AccessPath="/"
	locations := make(map[string]file.Location, len(layerFiles))
	for digest := range layerFiles {
		// Use NewVirtualLocationFromCoordinates with digest as FileSystemID
		coords := file.NewCoordinates("/", digest)
		locations[digest] = file.NewVirtualLocationFromCoordinates(coords, "/")
	}

	return &ContainerImageModel{
		tempDir:    tempDir,
		layerFiles: layerFiles,
		locations:  locations,
	}
}

// FilesByMediaType returns locations for layers matching the given media type patterns.
// Patterns support glob-style matching (e.g., "application/vnd.docker.ai*").
func (r *ContainerImageModel) FilesByMediaType(types ...string) ([]file.Location, error) {
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
func (r *ContainerImageModel) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	// Look up the temp file path using the digest stored in FileSystemID
	digest := location.FileSystemID
	info, ok := r.layerFiles[digest]
	if !ok {
		return nil, fmt.Errorf("no file found for digest %q", digest)
	}
	return os.Open(info.TempPath)
}

// FileMetadataByLocation returns metadata for the file at the given location.
func (r *ContainerImageModel) FileMetadataByLocation(_ file.Location) (m file.Metadata, err error) {
	return m, nil
}

// HasPath checks if the given path exists in the resolver.
func (r *ContainerImageModel) HasPath(path string) bool {
	// The virtual path is "/" for all files
	if path == "/" && len(r.layerFiles) > 0 {
		return true
	}
	return false
}

// FilesByPath returns locations for files matching the given paths.
func (r *ContainerImageModel) FilesByPath(_ ...string) ([]file.Location, error) {
	return nil, nil
}

// FilesByGlob returns locations for files matching the given glob patterns.
func (r *ContainerImageModel) FilesByGlob(_ ...string) ([]file.Location, error) {
	return nil, nil
}

// FilesByMIMEType returns locations for files with the given MIME types.
// This is not implemented for OCI model artifacts as we don't have MIME type detection.
func (r *ContainerImageModel) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	// Not implemented - OCI model artifacts don't have MIME type detection
	return nil, nil
}

// RelativeFileByPath returns a file at the given path relative to the reference location.
// This is not applicable for OCI model artifacts.
func (r *ContainerImageModel) RelativeFileByPath(_ file.Location, _ string) *file.Location {
	// Not implemented - no layer hierarchy in OCI model artifacts
	return nil
}

// AllLocations returns all file locations in the resolver.
func (r *ContainerImageModel) AllLocations(ctx context.Context) <-chan file.Location {
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
