package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"
	gguf_parser "github.com/gpustack/gguf-parser-go"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseGGUFModel parses a GGUF model file and returns the discovered package.
// This implementation only reads the header portion of the file, not the entire model.
func parseGGUFModel(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	// Create a temporary file for the library to parse
	// The library requires a file path, so we create a temp file
	tempFile, err := os.CreateTemp("", "syft-gguf-*.gguf")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	// Copy and validate the GGUF file header using LimitedReader to prevent OOM
	// We use LimitedReader to cap reads at maxHeaderSize (50MB)
	limitedReader := &io.LimitedReader{R: reader, N: maxHeaderSize}
	if err := copyHeader(tempFile, limitedReader); err != nil {
		tempFile.Close()
		return nil, nil, fmt.Errorf("failed to copy GGUF header: %w", err)
	}
	tempFile.Close()

	// Parse using gguf-parser-go with options to skip unnecessary data
	ggufFile, err := gguf_parser.ParseGGUFFile(tempPath,
		gguf_parser.SkipLargeMetadata(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse GGUF file: %w", err)
	}

	// Extract metadata
	metadata := ggufFile.Metadata()

	// Extract version separately (will be set on Package.Version)
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

	// If model name is not in metadata, use filename
	if metadata.Name == "" {
		metadata.Name = extractModelNameFromPath(reader.Path())
	}

	// Create package from metadata
	p := newGGUFPackage(
		syftMetadata,
		metadata.Name,
		modelVersion,
		metadata.License,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse GGUF file")
}

// computeKVMetadataHash computes a stable hash of the KV metadata for use as a global identifier
func computeKVMetadataHash(metadata gguf_parser.GGUFMetadataKVs) string {
	// Sort the KV pairs by key for stable hashing
	sortedKVs := make([]gguf_parser.GGUFMetadataKV, len(metadata))
	copy(sortedKVs, metadata)
	sort.Slice(sortedKVs, func(i, j int) bool {
		return sortedKVs[i].Key < sortedKVs[j].Key
	})

	// Marshal sorted KVs to JSON for stable hashing
	jsonBytes, err := json.Marshal(sortedKVs)
	if err != nil {
		log.Debugf("failed to marshal metadata for hashing: %v", err)
		return ""
	}

	// Compute xxhash
	hash := xxhash.Sum64(jsonBytes)
	return fmt.Sprintf("%016x", hash) // 16 hex chars (64 bits)
}

// extractVersion attempts to extract version from metadata KV pairs
func extractVersion(kvs gguf_parser.GGUFMetadataKVs) string {
	for _, kv := range kvs {
		if kv.Key == "general.version" {
			if v, ok := kv.Value.(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// extractModelNameFromPath extracts the model name from the file path
func extractModelNameFromPath(path string) string {
	// Get the base filename
	base := filepath.Base(path)

	// Remove .gguf extension
	name := strings.TrimSuffix(base, ".gguf")

	return name
}

// integrity check
var _ generic.Parser = parseGGUFModel
