package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseSafeTensorsFile decodes the JSON header of a single .safetensors file
// and emits a nameless package whose metadata is derived purely from the
// header bytes. Naming, license resolution, sibling enrichment, and cross-
// shard rollup are all the responsibility of safeTensorsMergeProcessor.
func parseSafeTensorsFile(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	header, _, err := readSafeTensorsHeader(&io.LimitedReader{R: reader, N: maxSafeTensorsHeaderSize + 8})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read safetensors header: %w", err)
	}

	md := pkg.SafeTensorsModelInfo{
		Format:       "safetensors",
		TensorCount:  uint64(len(header.tensors)),
		Quantization: normalizeDType(header.dominantDType()),
		ShardCount:   1,
		UserMetadata: userMetadataKeyValues(header.metadata),
		MetadataHash: header.metadataHash(),
	}
	if p := header.parameterCount(); p > 0 {
		md.Parameters = formatParameterCount(p)
	}

	p := newSafeTensorsPackage(
		&md,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)
	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse safetensors file")
}

// parseSafeTensorsIndex decodes a model.safetensors.index.json file for a
// sharded model and emits a nameless package recording tensor count, unique
// shard count, and (when present) the producer-declared total_size. Like
// parseSafeTensorsFile, naming and sibling enrichment happen in the merge
// processor.
func parseSafeTensorsIndex(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	var doc struct {
		Metadata struct {
			TotalSize json.Number `json:"total_size"`
		} `json:"metadata"`
		WeightMap map[string]string `json:"weight_map"`
	}
	if err := json.NewDecoder(reader).Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("failed to decode safetensors index JSON: %w", err)
	}

	shards := make(map[string]struct{}, 4)
	for _, shard := range doc.WeightMap {
		shards[shard] = struct{}{}
	}

	md := pkg.SafeTensorsModelInfo{
		Format:      "safetensors",
		TensorCount: uint64(len(doc.WeightMap)),
		ShardCount:  len(shards),
	}
	if doc.Metadata.TotalSize != "" {
		md.TotalSize = formatByteSize(doc.Metadata.TotalSize.String())
	}

	p := newSafeTensorsPackage(
		&md,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)
	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse safetensors index")
}

// formatParameterCount prints a count like 6_700_000_000 as "6.70B" using
// B/M/K thresholds matching the notation used by Hugging Face and Docker AI
// labels.
func formatParameterCount(n uint64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.2fB", float64(n)/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.2fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// formatByteSize turns a numeric string (bytes) into a human-friendly size
// like "71.90GB". Non-numeric inputs are passed through unchanged so producer-
// declared strings (e.g. "71.90GB" from a Docker AI config blob) survive.
func formatByteSize(s string) string {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return s
	}
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
		tb = gb * 1024
	)
	switch {
	case n >= tb:
		return fmt.Sprintf("%.2fTB", float64(n)/float64(tb))
	case n >= gb:
		return fmt.Sprintf("%.2fGB", float64(n)/float64(gb))
	case n >= mb:
		return fmt.Sprintf("%.2fMB", float64(n)/float64(mb))
	case n >= kb:
		return fmt.Sprintf("%.2fKB", float64(n)/float64(kb))
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// integrity checks
var (
	_ generic.Parser = parseSafeTensorsFile
	_ generic.Parser = parseSafeTensorsIndex
)
