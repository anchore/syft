/*
Package ai provides concrete Cataloger implementations for AI artifacts and machine learning models,
including support for GGUF (GPT-Generated Unified Format) model files.
*/
package ai

import (
	"context"
	"fmt"
	"io"
	"os"

	gguf_parser "github.com/gpustack/gguf-parser-go"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source/ocimodelsource"
)

const (
	catalogerName = "gguf-cataloger"
)

// ggufCataloger implements pkg.Cataloger with support for both file-based and OCI layer-based discovery.
type ggufCataloger struct {
	genericCataloger pkg.Cataloger
}

// NewGGUFCataloger returns a new cataloger instance for GGUF model files.
// It supports both traditional file-based discovery and OCI layer-aware discovery
// when the resolver implements OCIResolver.
func NewGGUFCataloger() pkg.Cataloger {
	return &ggufCataloger{
		genericCataloger: generic.NewCataloger(catalogerName).
			WithParserByGlobs(parseGGUFModel, "**/*.gguf"),
	}
}

// Name returns the cataloger name.
func (c *ggufCataloger) Name() string {
	return catalogerName
}

// Catalog discovers GGUF model packages from the given resolver.
// If the resolver implements OCIResolver, it uses layer-aware discovery.
// Otherwise, it falls back to glob-based file discovery.
func (c *ggufCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	// Check if the resolver supports OCI layer-aware access
	if ociResolver, ok := resolver.(ocimodelsource.OCIResolver); ok {
		log.Debug("using OCI layer-aware discovery for GGUF models")
		return c.catalogFromOCILayers(ctx, ociResolver)
	}

	// Fall back to generic glob-based discovery
	log.Debug("using glob-based discovery for GGUF models")
	return c.genericCataloger.Catalog(ctx, resolver)
}

// catalogFromOCILayers discovers GGUF models by querying OCI layers by media type.
func (c *ggufCataloger) catalogFromOCILayers(ctx context.Context, resolver ocimodelsource.OCIResolver) ([]pkg.Package, []artifact.Relationship, error) {
	// Find all GGUF layers by media type
	digests, err := resolver.LayerDigestsByMediaType(ocimodelsource.GGUFLayerMediaType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GGUF layer digests: %w", err)
	}

	if len(digests) == 0 {
		log.Debug("no GGUF layers found by media type")
		return nil, nil, nil
	}

	var packages []pkg.Package

	for idx, digest := range digests {
		select {
		case <-ctx.Done():
			return packages, nil, ctx.Err()
		default:
		}

		log.WithFields("digest", digest, "index", idx).Debug("processing GGUF layer")

		p, err := c.parseGGUFLayer(resolver, digest, idx)
		if err != nil {
			log.WithFields("digest", digest, "error", err).Warn("failed to parse GGUF layer")
			continue
		}

		if p != nil {
			packages = append(packages, *p)
		}
	}

	return packages, nil, nil
}

// parseGGUFLayer parses a single GGUF layer and returns the discovered package.
func (c *ggufCataloger) parseGGUFLayer(resolver ocimodelsource.OCIResolver, digest string, layerIndex int) (*pkg.Package, error) {
	// Fetch the layer content
	reader, err := resolver.LayerContentsByDigest(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch layer content: %w", err)
	}
	defer internal.CloseAndLogError(reader, digest)

	// Create a temporary file for the gguf-parser library
	tempFile, err := os.CreateTemp("", "syft-gguf-layer-*.gguf")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	// Copy and validate the GGUF header using LimitedReader to prevent OOM
	limitedReader := &io.LimitedReader{R: reader, N: maxHeaderSize}
	if err := copyHeader(tempFile, limitedReader); err != nil {
		tempFile.Close()
		return nil, fmt.Errorf("failed to copy GGUF header: %w", err)
	}
	tempFile.Close()

	// Parse using gguf-parser-go
	ggufFile, err := gguf_parser.ParseGGUFFile(tempPath,
		gguf_parser.SkipLargeMetadata(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GGUF file: %w", err)
	}

	// Extract metadata
	metadata := ggufFile.Metadata()
	modelVersion := extractVersion(ggufFile.Header.MetadataKV)

	// Convert to syft metadata structure
	syftMetadata := &pkg.GGUFFileHeader{
		Architecture:          metadata.Architecture,
		Quantization:          metadata.FileTypeDescriptor,
		Parameters:            uint64(metadata.Parameters),
		GGUFVersion:           uint32(ggufFile.Header.Version),
		TensorCount:           ggufFile.Header.TensorCount,
		RemainingKeyValues:    convertGGUFMetadataKVs(ggufFile.Header.MetadataKV),
		MetadataKeyValuesHash: computeKVMetadataHash(ggufFile.Header.MetadataKV),
	}

	// If model name is not in metadata, use a generated name
	modelName := metadata.Name
	if modelName == "" {
		modelName = fmt.Sprintf("model-layer-%d", layerIndex)
	}

	// Create a virtual location for the layer
	location := file.NewLocation("/").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)

	// Create package from metadata
	p := newGGUFPackage(
		syftMetadata,
		modelName,
		modelVersion,
		metadata.License,
		location,
	)

	return &p, nil
}
