package ai

import (
	"context"
	"fmt"
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseSafeTensorsFile decodes the JSON header of a single .safetensors file
// (also called once per shard for sharded models) and emits a nameless package
// whose metadata is derived purely from the header bytes. Naming, license
// resolution, sibling enrichment, and cross-shard rollup are all handled by
// safeTensorsMergeProcessor.
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

// integrity check
var _ generic.Parser = parseSafeTensorsFile
