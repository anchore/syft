package ocimodelsource

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ociModelResolver)(nil)

// ociModelResolver is a minimal file.Resolver implementation that provides access to
// GGUF header data fetched from OCI model artifacts via range-GET requests.
type ociModelResolver struct {
	tempFiles map[string]string // maps virtual path -> temporary file path
	locations []file.Location
}

// newOCIModelResolver creates a new resolver with the given temporary files.
func newOCIModelResolver(tempFiles map[string]string) *ociModelResolver {
	// Create locations for all temp files
	locations := make([]file.Location, 0, len(tempFiles))
	for virtualPath, tempPath := range tempFiles {
		// Use NewVirtualLocation: realPath is tempPath, accessPath is virtualPath
		locations = append(locations, file.NewVirtualLocation(tempPath, virtualPath))
	}

	return &ociModelResolver{
		tempFiles: tempFiles,
		locations: locations,
	}
}

// FileContentsByLocation returns the contents of the file at the given location.
func (r *ociModelResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	// Get the real path (temp file) from the location
	realPath := location.RealPath

	// Check if this is one of our managed files
	found := false
	for _, tempPath := range r.tempFiles {
		if tempPath == realPath {
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("location not found in resolver: %s", location.RealPath)
	}

	// Open and return the temp file
	f, err := os.Open(realPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open temp file: %w", err)
	}

	return f, nil
}

// FileMetadataByLocation returns metadata for the file at the given location.
func (r *ociModelResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	realPath := location.RealPath

	// Stat the temp file
	info, err := os.Stat(realPath)
	if err != nil {
		return file.Metadata{}, fmt.Errorf("failed to stat temp file: %w", err)
	}

	// Return basic metadata
	return file.Metadata{
		Path:     location.AccessPath, // Use AccessPath for virtual path
		Type:     stereofile.TypeRegular,
		FileInfo: info,
	}, nil
}

// HasPath checks if the given path exists in the resolver.
func (r *ociModelResolver) HasPath(path string) bool {
	_, exists := r.tempFiles[path]
	return exists
}

// FilesByPath returns locations for files matching the given paths.
func (r *ociModelResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var results []file.Location

	for _, path := range paths {
		for virtualPath, tempPath := range r.tempFiles {
			if virtualPath == path {
				results = append(results, file.NewVirtualLocation(tempPath, virtualPath))
			}
		}
	}

	return results, nil
}

// FilesByGlob returns locations for files matching the given glob patterns.
func (r *ociModelResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var results []file.Location

	for _, pattern := range patterns {
		for virtualPath, tempPath := range r.tempFiles {
			// Match against the virtual path
			matched, err := doublestar.Match(pattern, virtualPath)
			if err != nil {
				return nil, fmt.Errorf("failed to match pattern %q: %w", pattern, err)
			}

			if matched {
				results = append(results, file.NewVirtualLocation(tempPath, virtualPath))
			}
		}
	}

	return results, nil
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

// cleanup removes all temporary files managed by this resolver.
func (r *ociModelResolver) cleanup() error {
	var errs []error

	for virtualPath, tempPath := range r.tempFiles {
		if err := os.Remove(tempPath); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove temp file for %s: %w", virtualPath, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	return nil
}

// extractVirtualPath generates a virtual path for a GGUF layer.
// This simulates where the file would be in the artifact.
func extractVirtualPath(layerIndex int) string {
	return fmt.Sprintf("/model-layer-%d.gguf", layerIndex)
}

// createTempFileFromData creates a temporary file with the given data.
func createTempFileFromData(data []byte, virtualPath string) (string, error) {
	// Extract filename from virtual path for better temp file naming
	filename := filepath.Base(virtualPath)
	ext := filepath.Ext(filename)
	prefix := strings.TrimSuffix(filename, ext) + "-"

	// Create temp file
	tempFile, err := os.CreateTemp("", prefix+"*"+ext)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	// Write data
	if _, err := tempFile.Write(data); err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write to temp file: %w", err)
	}

	return tempFile.Name(), nil
}
