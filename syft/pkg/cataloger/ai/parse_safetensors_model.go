package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseSafeTensorsFile parses a single .safetensors file by reading only its
// JSON header, then enriches the resulting package with metadata from sibling
// config.json and README.md files when the resolver can find them.
func parseSafeTensorsFile(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	header, _, err := readSafeTensorsHeader(&io.LimitedReader{R: reader, N: maxSafeTensorsHeaderSize + 8})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read safetensors header: %w", err)
	}

	md := pkg.SafeTensorsMetadata{
		Format:       "safetensors",
		TensorCount:  uint64(len(header.tensors)),
		Quantization: normalizeDType(header.dominantDType()),
		ShardCount:   1,
		UserMetadata: header.metadata,
		MetadataHash: header.metadataHash(),
	}
	if p := header.parameterCount(); p > 0 {
		md.Parameters = formatParameterCount(p)
	}

	name, version, license := enrichFromSiblings(resolver, reader.Path(), &md)
	if name == "" {
		name = modelNameFromPath(reader.Path())
	}

	p := newSafeTensorsPackage(
		&md,
		name,
		version,
		license,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse safetensors file")
}

// parseSafeTensorsIndex parses a model.safetensors.index.json file for a sharded
// model. The index lists every tensor and the shard file it lives in; from this
// we derive tensor count, unique shard count, and (when present) the producer-
// declared total_size.
func parseSafeTensorsIndex(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
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

	md := pkg.SafeTensorsMetadata{
		Format:      "safetensors",
		TensorCount: uint64(len(doc.WeightMap)),
		ShardCount:  len(shards),
	}
	if doc.Metadata.TotalSize != "" {
		md.TotalSize = formatByteSize(doc.Metadata.TotalSize.String())
	}

	name, version, license := enrichFromSiblings(resolver, reader.Path(), &md)
	if name == "" {
		name = modelNameFromIndexPath(reader.Path())
	}

	p := newSafeTensorsPackage(
		&md,
		name,
		version,
		license,
		reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
	)

	return []pkg.Package{p}, nil, unknown.IfEmptyf([]pkg.Package{p}, "unable to parse safetensors index")
}

// enrichFromSiblings looks for a sibling config.json and README.md next to the
// safetensors artifact and folds their values into the metadata struct. It
// returns a name, version, and license string derived from those sources, with
// the caller free to fall back to a filename-derived default.
func enrichFromSiblings(resolver file.Resolver, sourcePath string, md *pkg.SafeTensorsMetadata) (name, version, license string) {
	if resolver == nil {
		return "", "", ""
	}
	dir := path.Dir(sourcePath)

	if cfg := readSiblingJSON(resolver, path.Join(dir, "config.json")); cfg != nil {
		if md.Architecture == "" && len(cfg.Architectures) > 0 {
			md.Architecture = cfg.Architectures[0]
		}
		if md.TorchDtype == "" {
			md.TorchDtype = cfg.TorchDtype
		}
		if md.TransformersVersion == "" {
			md.TransformersVersion = cfg.TransformersVersion
		}
		if cfg.NameOrPath != "" {
			name = path.Base(cfg.NameOrPath)
		}
	}

	if fm := readReadmeFrontmatter(resolver, path.Join(dir, "README.md")); fm != nil {
		if license == "" {
			license = fm.License
		}
		if name == "" && len(fm.BaseModel) > 0 {
			name = path.Base(fm.BaseModel[0])
		}
	}

	return name, version, license
}

// hfConfig is a minimal projection of Hugging Face config.json fields we care about.
type hfConfig struct {
	Architectures       []string `json:"architectures"`
	TorchDtype          string   `json:"torch_dtype"`
	TransformersVersion string   `json:"transformers_version"`
	NameOrPath          string   `json:"_name_or_path"`
}

func readSiblingJSON(resolver file.Resolver, p string) *hfConfig {
	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return nil
	}
	rc, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return nil
	}
	defer internal.CloseAndLogError(rc, p)

	var cfg hfConfig
	if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
		log.Debugf("failed to decode %s: %v", p, err)
		return nil
	}
	return &cfg
}

// readmeFrontmatter holds the subset of YAML frontmatter fields we extract.
type readmeFrontmatter struct {
	License   string   `yaml:"license"`
	BaseModel []string `yaml:"base_model"`
}

// readReadmeFrontmatter extracts the leading YAML frontmatter block from a README.
// The block is delimited by "---" lines at the start of the file.
func readReadmeFrontmatter(resolver file.Resolver, p string) *readmeFrontmatter {
	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return nil
	}
	rc, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return nil
	}
	defer internal.CloseAndLogError(rc, p)

	buf, err := io.ReadAll(io.LimitReader(rc, 1024*1024))
	if err != nil {
		return nil
	}
	return parseFrontmatter(buf)
}

// parseFrontmatter pulls the YAML block between the first and second "---" lines
// of a file (if present) and decodes known fields from it.
func parseFrontmatter(buf []byte) *readmeFrontmatter {
	trimmed := bytes.TrimLeft(buf, "\xef\xbb\xbf \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("---")) {
		return nil
	}
	rest := trimmed[3:]
	// trim the newline directly following the opening delimiter
	if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[i+1:]
	}
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return nil
	}
	var fm readmeFrontmatter
	if err := yaml.Unmarshal(rest[:end], &fm); err != nil {
		log.Debugf("failed to parse README frontmatter: %v", err)
		return nil
	}
	// base_model may also appear as a scalar; yaml.Unmarshal will fail silently in that case.
	if fm.License == "" && len(fm.BaseModel) == 0 {
		var alt struct {
			License   string `yaml:"license"`
			BaseModel string `yaml:"base_model"`
		}
		if err := yaml.Unmarshal(rest[:end], &alt); err == nil {
			fm.License = alt.License
			if alt.BaseModel != "" {
				fm.BaseModel = []string{alt.BaseModel}
			}
		}
	}
	return &fm
}

// modelNameFromPath turns "/models/foo/model.safetensors" into "foo".
// For a bare filename "weights.safetensors" we return "weights".
func modelNameFromPath(p string) string {
	base := strings.TrimSuffix(filepath.Base(p), ".safetensors")
	dir := filepath.Base(filepath.Dir(p))
	if dir != "" && dir != "." && dir != string(filepath.Separator) {
		return dir
	}
	return base
}

// modelNameFromIndexPath derives a model name from the index filename's parent
// directory, defaulting to "safetensors-model" if no useful directory name exists.
func modelNameFromIndexPath(p string) string {
	dir := filepath.Base(filepath.Dir(p))
	if dir != "" && dir != "." && dir != string(filepath.Separator) {
		return dir
	}
	return "safetensors-model"
}

// formatParameterCount prints a count like 6_700_000_000 as "6.7B" using B/M/K
// thresholds matching the notation used by Hugging Face and Docker AI labels.
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

// formatByteSize turns a numeric string (bytes) into a human-friendly size like
// "71.90GB". Non-numeric inputs are passed through unchanged so we never lose
// producer-declared strings such as "71.90GB".
func formatByteSize(s string) string {
	var n uint64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n == 0 {
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
