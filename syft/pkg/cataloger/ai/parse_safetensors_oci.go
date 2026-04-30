package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// Docker AI OCI media types used by Docker Model Runner artifacts.
const (
	dockerAIModelConfigMediaType = "application/vnd.docker.ai.model.config.v0.1+json"
	dockerAIModelFileMediaType   = "application/vnd.docker.ai.model.file"
	dockerAILicenseMediaType     = "application/vnd.docker.ai.license"
)

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

// parseSafeTensorsOCIConfig parses a Docker AI model-config blob. When the blob
// advertises format=="safetensors" it emits a single named package whose
// metadata is enriched by scanning sibling OCI layers (README.md for license +
// base_model name, config.json for architecture, LICENSE text for a license
// fallback). For any other format it emits nothing so the GGUF cataloger can
// claim the image.
func parseSafeTensorsOCIConfig(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
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

	md := pkg.SafeTensorsMetadata{
		Format:       "safetensors",
		Quantization: cfg.Config.Quantization,
		Parameters:   cfg.Config.Parameters,
		TotalSize:    cfg.Config.Size,
	}
	if n, err := cfg.Config.SafeTensors.TensorCount.Int64(); err == nil && n > 0 {
		md.TensorCount = uint64(n)
	}

	name, license := enrichFromDockerAILayers(resolver, &md)

	p := newSafeTensorsPackage(
		&md,
		name,
		"",
		license,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse docker AI safetensors config")
}

// enrichFromDockerAILayers walks sibling Docker AI layers via the OCI resolver
// and mines them for a model name, architecture, and license. README.md carries
// YAML frontmatter with license + base_model; HF config.json carries
// architectures/torch_dtype/transformers_version; the vnd.docker.ai.license
// blob is plain license text.
func enrichFromDockerAILayers(resolver file.Resolver, md *pkg.SafeTensorsMetadata) (name, license string) {
	ociResolver, ok := resolver.(file.OCIMediaTypeResolver)
	if !ok {
		return "", ""
	}

	modelFileLocations, err := ociResolver.FilesByMediaType(dockerAIModelFileMediaType)
	if err != nil {
		log.Debugf("failed to list docker AI model-file layers: %v", err)
	}
	for _, loc := range modelFileLocations {
		rc, err := resolver.FileContentsByLocation(loc)
		if err != nil {
			continue
		}
		buf, readErr := io.ReadAll(io.LimitReader(rc, 4*1024*1024))
		internal.CloseAndLogError(rc, loc.RealPath)
		if readErr != nil {
			continue
		}
		classifyAndMerge(buf, md, &name, &license)
	}

	if license == "" {
		license = readDockerAILicense(resolver, ociResolver)
	}

	return name, license
}

// classifyAndMerge sniffs a vnd.docker.ai.model.file blob (which can be README.md,
// config.json, generation_config.json, tokenizer.json, etc.) and folds useful
// fields into the metadata struct and out-parameters.
func classifyAndMerge(buf []byte, md *pkg.SafeTensorsMetadata, name, license *string) {
	trimmed := trimLeadingWhitespace(buf)
	switch {
	case hasPrefix(trimmed, "---"):
		if fm := parseFrontmatter(buf); fm != nil {
			if *license == "" {
				*license = fm.License
			}
			if *name == "" && len(fm.BaseModel) > 0 {
				*name = lastPathSegment(fm.BaseModel[0])
			}
		}
	case hasPrefix(trimmed, "{"):
		var cfg hfConfig
		if err := json.Unmarshal(buf, &cfg); err != nil {
			return
		}
		if md.Architecture == "" && len(cfg.Architectures) > 0 {
			md.Architecture = cfg.Architectures[0]
		}
		if md.TorchDtype == "" {
			md.TorchDtype = cfg.TorchDtype
		}
		if md.TransformersVersion == "" {
			md.TransformersVersion = cfg.TransformersVersion
		}
		if *name == "" && cfg.NameOrPath != "" {
			*name = lastPathSegment(cfg.NameOrPath)
		}
	}
}

// readDockerAILicense extracts a short license identifier from the first line
// of a vnd.docker.ai.license layer. Docker packages the full license text, so
// we only peek at a prefix looking for well-known titles like "Apache License".
func readDockerAILicense(resolver file.Resolver, ociResolver file.OCIMediaTypeResolver) string {
	locations, err := ociResolver.FilesByMediaType(dockerAILicenseMediaType)
	if err != nil || len(locations) == 0 {
		return ""
	}
	rc, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return ""
	}
	defer internal.CloseAndLogError(rc, locations[0].RealPath)

	buf, err := io.ReadAll(io.LimitReader(rc, 2048))
	if err != nil {
		return ""
	}
	text := strings.ToLower(string(buf))
	switch {
	case strings.Contains(text, "apache license") && strings.Contains(text, "version 2.0"):
		return "Apache-2.0"
	case strings.Contains(text, "mit license"):
		return "MIT"
	case strings.Contains(text, "bsd 3-clause"):
		return "BSD-3-Clause"
	case strings.Contains(text, "bsd 2-clause"):
		return "BSD-2-Clause"
	case strings.Contains(text, "gnu general public license") && strings.Contains(text, "version 3"):
		return "GPL-3.0"
	}
	return ""
}

func hasPrefix(b []byte, s string) bool {
	return len(b) >= len(s) && string(b[:len(s)]) == s
}

func trimLeadingWhitespace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	// strip a leading UTF-8 BOM if present
	if len(b)-i >= 3 && b[i] == 0xEF && b[i+1] == 0xBB && b[i+2] == 0xBF {
		i += 3
	}
	return b[i:]
}

func lastPathSegment(s string) string {
	if i := strings.LastIndexAny(s, "/\\"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// integrity check
var _ generic.Parser = parseSafeTensorsOCIConfig
