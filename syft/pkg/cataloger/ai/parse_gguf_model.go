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
	"github.com/anchore/syft/internal/tmpdir"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseGGUFModel parses a GGUF model file and returns the discovered package.
// This implementation only reads the header portion of the file, not the entire model.
func parseGGUFModel(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.FullNestedPath())

	td := tmpdir.FromContext(ctx)
	if td == nil {
		return nil, nil, fmt.Errorf("no temp dir factory in context")
	}
	tempFile, cleanup, err := td.NewFile("syft-gguf-*.gguf")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer cleanup()

	// copy and validate the GGUF file header (bounded to maxHeaderSize)
	if err := copyHeader(tempFile, reader); err != nil {
		tempFile.Close()
		return nil, nil, fmt.Errorf("failed to copy GGUF header: %w", err)
	}
	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		tempFile.Close()
		return nil, nil, fmt.Errorf("failed to rewind GGUF header: %w", err)
	}
	if err := validateGGUFHeader(tempFile); err != nil {
		tempFile.Close()
		return nil, nil, fmt.Errorf("invalid GGUF header: %w", err)
	}
	err = extendToModelSize(tempFile, modelSize(resolver, reader.Location))
	tempFile.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extend GGUF header copy: %w", err)
	}

	// Parse using gguf-parser-go with options to skip unnecessary data
	ggufFile, err := gguf_parser.ParseGGUFFile(tempFile.Name(),
		gguf_parser.SkipLargeMetadata(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse GGUF file: %w", err)
	}

	// Extract metadata
	metadata := ggufFile.Metadata()

	// Extract version separately (will be set on Package.Version)
	modelVersion := extractVersion(ggufFile.Header.MetadataKV)

	metadataHash, err := computeKVMetadataHash(ggufFile.Header.MetadataKV)
	if err != nil {
		return nil, nil, err
	}

	// Convert to syft metadata structure
	syftMetadata := &pkg.GGUFFileHeader{
		Architecture:          metadata.Architecture,
		Quantization:          metadata.FileTypeDescriptor,
		Parameters:            uint64(metadata.Parameters),
		GGUFVersion:           uint32(ggufFile.Header.Version),
		TensorCount:           ggufFile.Header.TensorCount,
		RemainingKeyValues:    convertGGUFMetadataKVs(ggufFile.Header.MetadataKV),
		MetadataKeyValuesHash: metadataHash,
	}

	// If model name is not in metadata, use filename
	if metadata.Name == "" {
		metadata.Name = extractModelNameFromPath(reader.Path())
	}

	// Create package from metadata
	p := newGGUFPackage(
		ctx,
		syftMetadata,
		metadata.Name,
		modelVersion,
		metadata.License,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return []pkg.Package{p}, nil, nil
}

// modelSize returns the size of the model file, or 0 when the resolver can't say.
func modelSize(resolver file.Resolver, loc file.Location) int64 {
	if resolver == nil {
		return 0
	}
	m, err := resolver.FileMetadataByLocation(loc)
	if err != nil || m.FileInfo == nil {
		return 0
	}
	return m.Size()
}

// extendToModelSize grows the header copy to the model's real size, since the parser checks the tensor data
// the header declares against the file size. It must run after validation so the header itself never reads
// from the hole. The file is marked sparse first so the hole takes no disk space; where that isn't possible
// the copy is left as is, and the parser rejects models larger than it.
func extendToModelSize(f *os.File, size int64) error {
	if size <= maxHeaderSize {
		return nil
	}
	if err := markSparse(f); err != nil {
		log.Debugf("unable to mark GGUF header copy sparse, not extending it: %v", err)
		return nil
	}
	return f.Truncate(size)
}

// computeKVMetadataHash computes a stable hash of the sanitized KV metadata for use as a global identifier
func computeKVMetadataHash(metadata gguf_parser.GGUFMetadataKVs) (string, error) {
	// Sort the KV pairs by key for stable hashing
	sortedKVs := make([]gguf_parser.GGUFMetadataKV, len(metadata))
	for i, kv := range metadata {
		kv.Value = sanitizeGGUFValue(kv.Value)
		sortedKVs[i] = kv
	}
	sort.Slice(sortedKVs, func(i, j int) bool {
		return sortedKVs[i].Key < sortedKVs[j].Key
	})

	// Marshal sorted KVs to JSON for stable hashing
	jsonBytes, err := json.Marshal(sortedKVs)
	if err != nil {
		return "", fmt.Errorf("failed to marshal GGUF metadata for hashing: %w", err)
	}

	// Compute xxhash
	hash := xxhash.Sum64(jsonBytes)
	return fmt.Sprintf("%016x", hash), nil // 16 hex chars (64 bits)
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
	// we do not want to return a name from filepath if it's not a distinct gguf file
	if !strings.Contains(path, ".gguf") {
		return ""
	}
	// Get the base filename
	base := filepath.Base(path)

	// Remove .gguf extension
	name := strings.TrimSuffix(base, ".gguf")

	return name
}

// integrity check
var _ generic.Parser = parseGGUFModel
