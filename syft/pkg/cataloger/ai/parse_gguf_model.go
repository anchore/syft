package ai

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	gguf_parser "github.com/gpustack/gguf-parser-go"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const unknownGGUFData = "unknown"

// parseGGUFModel parses a GGUF model file and returns the discovered package.
// This implementation only reads the header portion of the file, not the entire model.
func parseGGUFModel(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	// Read and validate the GGUF file header using LimitedReader to prevent OOM
	// We use LimitedReader to cap reads at maxHeaderSize (50MB)
	limitedReader := &io.LimitedReader{R: reader, N: maxHeaderSize}
	headerReader := &ggufHeaderReader{reader: limitedReader}
	headerData, err := headerReader.readHeader()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read GGUF header: %w", err)
	}

	// Create a temporary file for the library to parse
	// The library requires a file path, so we create a temp file
	tempFile, err := os.CreateTemp("", "syft-gguf-*.gguf")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	// Write the validated header data to temp file
	if _, err := tempFile.Write(headerData); err != nil {
		tempFile.Close()
		return nil, nil, fmt.Errorf("failed to write to temp file: %w", err)
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

	// Convert to syft metadata structure
	syftMetadata := &pkg.GGUFFileHeader{
		ModelFormat:     "gguf",
		ModelName:       metadata.Name,
		ModelVersion:    extractVersion(ggufFile.Header.MetadataKV),
		License:         metadata.License,
		Architecture:    metadata.Architecture,
		Quantization:    metadata.FileTypeDescriptor,
		Parameters:      uint64(metadata.Parameters),
		GGUFVersion:     uint32(ggufFile.Header.Version),
		TensorCount:     ggufFile.Header.TensorCount,
		Header:          convertGGUFMetadataKVs(ggufFile.Header.MetadataKV),
		TruncatedHeader: false, // We read the full header
		Hash:            "",    // Will be computed in newGGUFPackage
	}

	// If model name is not in metadata, use filename
	if syftMetadata.ModelName == "" {
		syftMetadata.ModelName = extractModelNameFromPath(reader.Path())
	}

	// If version is still unknown, try to infer from name
	if syftMetadata.ModelVersion == unknownGGUFData {
		syftMetadata.ModelVersion = extractVersionFromName(syftMetadata.ModelName)
	}

	// Create package from metadata
	p := newGGUFPackage(
		syftMetadata,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse GGUF file")
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
	return unknownGGUFData
}

// extractVersionFromName tries to extract version from model name
func extractVersionFromName(_ string) string {
	// Look for version patterns like "v1.0", "1.5b", "3.0", etc.
	// For now, return unknown - this could be enhanced with regex
	return unknownGGUFData
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
