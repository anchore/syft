package ocimodelsource

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/anchore/syft/syft/file"
)

var _ file.Resolver = (*ociModelResolver)(nil)

// ociModelResolver is a file.Resolver implementation that provides access to
// GGUF header data fetched from OCI model artifacts via range-GET requests.
// It also implements OCIResolver for layer-aware access patterns.
type ociModelResolver struct {
	tempFiles map[string]string // maps virtual path -> temporary file path
	locations []file.Location

	// OCI layer-aware fields
	client   *RegistryClient // registry client for fetching layers
	ref      name.Reference  // OCI reference for the artifact
	manifest *v1.Manifest    // manifest containing layer information
}

// newOCIModelResolver creates a new resolver with the given temporary files and OCI context.
func newOCIModelResolver(tempFiles map[string]string, client *RegistryClient, ref name.Reference, manifest *v1.Manifest) *ociModelResolver {
	// Create locations for all temp files
	locations := make([]file.Location, 0, len(tempFiles))
	for virtualPath, tempPath := range tempFiles {
		// Use NewVirtualLocation: realPath is tempPath, accessPath is virtualPath
		locations = append(locations, file.NewVirtualLocation(tempPath, virtualPath))
	}

	return &ociModelResolver{
		tempFiles: tempFiles,
		locations: locations,
		client:    client,
		ref:       ref,
		manifest:  manifest,
	}
}

// FileContentsByLocation returns the contents of the file at the given location.
func (r *ociModelResolver) FileContentsByLocation(_ file.Location) (io.ReadCloser, error) {
	return nil, nil
}

// FileMetadataByLocation returns metadata for the file at the given location.
func (r *ociModelResolver) FileMetadataByLocation(_ file.Location) (m file.Metadata, err error) {
	return m, nil
}

// HasPath checks if the given path exists in the resolver.
func (r *ociModelResolver) HasPath(path string) bool {
	_, exists := r.tempFiles[path]
	return exists
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

// LayerDigestsByMediaType returns the digests of all layers with the given media type.
// This allows catalogers to discover layers of interest without pre-fetching content.
func (r *ociModelResolver) LayerDigestsByMediaType(mediaType string) ([]string, error) {
	if r.manifest == nil {
		return nil, fmt.Errorf("manifest not available")
	}

	var digests []string
	for _, layer := range r.manifest.Layers {
		if string(layer.MediaType) == mediaType {
			digests = append(digests, layer.Digest.String())
		}
	}
	return digests, nil
}

// LayerContentsByDigest returns a reader for the layer content identified by digest.
// The caller is responsible for closing the returned reader.
func (r *ociModelResolver) LayerContentsByDigest(digest string) (io.ReadCloser, error) {
	if r.client == nil || r.ref == nil {
		return nil, fmt.Errorf("registry client or reference not available")
	}

	// Fetch the layer using the registry client
	repo := r.ref.Context()
	layer, err := remote.Layer(repo.Digest(digest), r.client.options...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch layer %s: %w", digest, err)
	}

	// Return the compressed layer content
	reader, err := layer.Compressed()
	if err != nil {
		return nil, fmt.Errorf("failed to get layer reader for %s: %w", digest, err)
	}

	return reader, nil
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

// This simulates where the file would be in the artifact.
// This is not used for the location in package
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
