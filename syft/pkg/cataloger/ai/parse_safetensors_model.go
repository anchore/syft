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

	header, err := readSafeTensorsHeader(&io.LimitedReader{R: reader, N: maxSafeTensorsHeaderSize + 8})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read safetensors header: %w", err)
	}

	// ShardCount is intentionally not set here: the merge processor is the single
	// owner of ShardCount and derives it from the number of shards in the group.
	md := pkg.SafeTensorsModelInfo{
		Format:       "safetensors",
		TensorCount:  uint64(len(header.tensors)),
		Parameters:   header.parameterCount(),
		Quantization: normalizeDType(header.dominantDType()),
		UserMetadata: userMetadataKeyValues(header.metadata),
		MetadataHash: header.metadataHash(),
	}

	p := newSafeTensorsPackage(
		&md,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)
	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse safetensors file")
}

// integrity check
var _ generic.Parser = parseSafeTensorsFile
