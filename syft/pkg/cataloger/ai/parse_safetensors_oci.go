package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// Docker AI OCI media types used by Docker Model Runner artifacts.
const (
	dockerAIModelFileMediaType   = "application/vnd.docker.ai.model.file"
	dockerAILicenseMediaType     = "application/vnd.docker.ai.license"
	dockerAISafeTensorsMediaType = "application/vnd.docker.ai.safetensors"
)

// dockerAIModelConfigMediaTypes are the model-config schema versions this
// cataloger understands. Versions are enumerated explicitly rather than matched
// with a wildcard so that a future, potentially breaking, config schema is not
// silently consumed; add a new version here only after confirming the fields we
// parse still apply.
var dockerAIModelConfigMediaTypes = []string{
	"application/vnd.docker.ai.model.config.v0.1+json",
	"application/vnd.docker.ai.model.config.v0.2+json",
}

// dockerAIModelConfig mirrors the JSON shape of the vnd.docker.ai.model.config
// blob written by Docker Model Runner for AI artifacts. Only fields we use are
// declared; unknown fields are ignored.
type dockerAIModelConfig struct {
	Config struct {
		Format       string `json:"format"`
		Quantization string `json:"quantization"`
		Parameters   string `json:"parameters"`
		Size         string `json:"size"`
		SafeTensors  struct {
			TensorCount json.Number `json:"tensor_count"`
		} `json:"safetensors"`
	} `json:"config"`
}

// parseSafeTensorsOCIConfig decodes the Docker AI model-config blob
func parseSafeTensorsOCIConfig(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	body, err := io.ReadAll(io.LimitReader(reader, 1024*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read docker AI model config: %w", err)
	}

	var cfg dockerAIModelConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, nil, fmt.Errorf("failed to decode docker AI model config: %w", err)
	}

	if !strings.EqualFold(cfg.Config.Format, "safetensors") {
		return nil, nil, nil
	}

	md := pkg.SafeTensorsModelInfo{
		Format:       "safetensors",
		Quantization: cfg.Config.Quantization,
		Parameters:   cfg.Config.Parameters,
		TotalSize:    cfg.Config.Size,
	}
	if n, err := cfg.Config.SafeTensors.TensorCount.Int64(); err == nil && n > 0 {
		md.TensorCount = uint64(n)
	}

	p := newSafeTensorsPackage(
		&md,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)
	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse docker AI safetensors config")
}

// parseSafeTensorsOCILayer decodes the JSON header of a SafeTensors weight
// layer fetched from an OCI model artifact
func parseSafeTensorsOCILayer(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	header, err := readSafeTensorsHeader(&io.LimitedReader{R: reader, N: maxSafeTensorsHeaderSize + 8})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read safetensors layer header: %w", err)
	}

	md := pkg.SafeTensorsModelInfo{
		Format:       "safetensors",
		TensorCount:  uint64(len(header.tensors)),
		Quantization: normalizeDType(header.dominantDType()),
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
	return []pkg.Package{p}, nil, nil
}

// integrity checks
var (
	_ generic.Parser = parseSafeTensorsOCIConfig
	_ generic.Parser = parseSafeTensorsOCILayer
)
