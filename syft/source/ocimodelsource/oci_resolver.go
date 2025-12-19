package ocimodelsource

import (
	"io"

	"github.com/anchore/syft/syft/file"
)

// OCIResolver extends file.Resolver with OCI layer-aware capabilities.
// This allows catalogers to discover and access content by media type
// rather than relying solely on file paths/globs.
type OCIResolver interface {
	file.Resolver

	// LayerDigestsByMediaType returns the digests of all layers with the given media type.
	// This provides "locations" for content without pre-fetching everything.
	LayerDigestsByMediaType(mediaType string) ([]string, error)

	// LayerContentsByDigest returns a reader for the layer content identified by digest.
	// Implementations may use range-GET for partial reads or full blob fetch.
	// The caller is responsible for closing the returned reader.
	LayerContentsByDigest(digest string) (io.ReadCloser, error)
}

// Verify ociModelResolver implements OCIResolver at compile time.
var _ OCIResolver = (*ociModelResolver)(nil)
