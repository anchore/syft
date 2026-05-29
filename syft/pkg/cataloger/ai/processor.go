package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/cespare/xxhash/v2"
	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

// ociGroupKey is the sentinel grouping key for every safetensors package that
// originated from an OCI model artifact. The ContainerImageModel resolver gives
// each layer the virtual RealPath "/" regardless of layer media type, so all
// safetensors packages from a single OCI scan collapse into one group.
const ociGroupKey = "@oci@"

// ggufMergeProcessor consolidates multiple GGUF packages into a single package
// representing the AI model. When scanning OCI images with multiple layers,
// each layer may produce a separate package. This processor finds the package
// with a name and merges metadata from nameless packages into its GGUFFileParts field.
// Only packages with a non-empty name are returned in the final result.
func ggufMergeProcessor(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil {
		return pkgs, rels, err
	}
	if len(pkgs) == 0 {
		return pkgs, rels, err
	}

	// Separate packages with names from those without
	var namedPkgs []pkg.Package
	var namelessHeaders []pkg.GGUFFileHeader

	for _, p := range pkgs {
		if p.Name != "" {
			namedPkgs = append(namedPkgs, p)
		} else {
			if header, ok := p.Metadata.(pkg.GGUFFileHeader); ok {
				// We do not want a kv hash for nameless headers
				header.MetadataKeyValuesHash = ""
				namelessHeaders = append(namelessHeaders, header)
			}
		}
	}

	// If there are no named packages, return nothing
	if len(namedPkgs) == 0 {
		return nil, rels, err
	}

	// merge nameless headers into a single named package;
	// if there are multiple named packages, return them without trying to merge headers.
	// we cannot determine which nameless headers belong to which package
	// this is because the order we receive the gguf headers in is not guaranteed
	// to match the layer order in the original oci image
	if len(namedPkgs) == 1 && len(namelessHeaders) > 0 {
		winner := &namedPkgs[0]
		if header, ok := winner.Metadata.(pkg.GGUFFileHeader); ok {
			header.Parts = namelessHeaders
			winner.Metadata = header
		}
	}

	return namedPkgs, rels, err
}

// safeTensorsMergeProcessor owns naming, license resolution, etc
//  1. groups all nameless packages by parent directory (or a single sentinel
//     for OCI artifacts, since the ContainerImageModel resolver puts every
//     layer at virtual path "/");
//  2. merges the per-shard metadata (tensor count, dominant dtype, total size,
//     UserMetadata, rollup MetadataHash) into one package per group;
//  3. enriches the merged package by consulting the resolver ONCE per group —
//     sibling config.json + README.md for dir scans, the model-file companion
//     layers + license layer for OCI — and attaches those locations as
//     supporting evidence;
//  4. picks a name via the precedence chain
//     config.json _name_or_path → Architecture-Parameters → parent-dir
//     and drops the group when none of those produced a name (no opaque
//     fallback / no MetadataHash-as-name).
func safeTensorsMergeProcessor(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil || len(pkgs) == 0 {
		return pkgs, rels, err
	}

	// Defensively split off non-safetensors packages — the cataloger only emits
	// SafeTensorsModelInfo today, but this keeps the processor robust if other
	// types ever flow through.
	var stPkgs, other []pkg.Package
	for _, p := range pkgs {
		if _, ok := p.Metadata.(pkg.SafeTensorsModelInfo); ok {
			stPkgs = append(stPkgs, p)
			continue
		}
		other = append(other, p)
	}
	if len(stPkgs) == 0 {
		return pkgs, rels, err
	}

	groups := groupSafeTensorsPackages(stPkgs)

	// Deterministic iteration order so the SBOM doesn't depend on map order.
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := other
	for _, key := range keys {
		merged := mergeSafeTensorsGroup(groups[key])
		nameOrPath := enrichSafeTensorsGroup(ctx, resolver, key, &merged)
		name := pickSafeTensorsName(merged, key, nameOrPath)
		if name == "" {
			continue // drop unnameable groups, per design (no opaque fallback)
		}
		merged.Name = name
		merged.SetID()
		out = append(out, merged)
	}
	return out, rels, nil
}

// groupSafeTensorsPackages buckets packages by the parent directory of their
// primary-evidence location, or the OCI sentinel when the location lives at
// the ContainerImageModel resolver's virtual "/" path.
// TODO: assemble a test where there are cases for DIR ran into for a single scan
// - safe tensors at the top level as well as sub directories
func groupSafeTensorsPackages(pkgs []pkg.Package) map[string][]pkg.Package {
	out := make(map[string][]pkg.Package)
	for _, p := range pkgs {
		key := safeTensorsGroupKey(p)
		if key == "" {
			continue
		}
		out[key] = append(out[key], p)
	}
	return out
}

func safeTensorsGroupKey(p pkg.Package) string {
	loc := primaryEvidenceLocation(p)
	if loc == nil {
		return ""
	}
	if loc.RealPath == "/" {
		return ociGroupKey
	}
	return path.Dir(loc.RealPath)
}

func primaryEvidenceLocation(p pkg.Package) *file.Location {
	locs := p.Locations.ToSlice()
	for i, l := range locs {
		if l.Annotations != nil && l.Annotations[pkg.EvidenceAnnotationKey] == pkg.PrimaryEvidenceAnnotation {
			return &locs[i]
		}
	}
	if len(locs) > 0 {
		return &locs[0]
	}
	return nil
}

// mergeSafeTensorsGroup folds a group's per-member metadata into a single
// package. Members are classified into two buckets to avoid double-counting:
//
//   - "aggregate" members have producer-declared totals (TensorCount, TotalSize,
//     ShardCount, Parameters) but no MetadataHash — these are the Docker AI
//     config blob and the sharded-index file.
//   - "shard" members have a content-derived MetadataHash and per-shard counts —
//     these are the individual .safetensors header parsers, both dir-scan and
//     OCI weight-layer.
//
// Aggregate values are the source of truth for the merged totals when present;
// shards contribute Quantization, UserMetadata, the rollup MetadataHash, and
// (for multi-shard models) the Parts breakdown.
func mergeSafeTensorsGroup(members []pkg.Package) pkg.Package {
	locSet := unionLocations(members)
	aggregates, shards := bucketSafeTensorsMembers(members)

	merged := pkg.SafeTensorsModelInfo{Format: "safetensors"}
	mergeAggregatesInto(&merged, aggregates)
	shardTensorTotal, hashes := mergeShardsInto(&merged, shards)

	if merged.TensorCount == 0 {
		merged.TensorCount = shardTensorTotal
	}
	if merged.ShardCount == 0 {
		if len(shards) > 0 {
			merged.ShardCount = len(shards)
		} else {
			merged.ShardCount = 1
		}
	}
	merged.MetadataHash = rollupHash(hashes)

	// Parts only carry value for multi-shard models; for a single shard the
	// outer view already exposes every per-shard field.
	if len(shards) > 1 {
		parts := append([]pkg.SafeTensorsModelInfo(nil), shards...)
		sort.Slice(parts, func(i, j int) bool {
			return parts[i].MetadataHash < parts[j].MetadataHash
		})
		merged.Parts = parts
	}

	return pkg.Package{
		Locations: locSet,
		Type:      pkg.ModelPkg,
		Metadata:  merged,
	}
}

// mergeAggregatesInto folds aggregate-declared totals (config blob or sharded
// index) into merged. First non-empty wins, so the order aggregates are passed
// in determines tie-breaking — in practice there is one config blob and one
// index per group, never two of the same kind.
func mergeAggregatesInto(merged *pkg.SafeTensorsModelInfo, aggregates []pkg.SafeTensorsModelInfo) {
	for _, a := range aggregates {
		if merged.TensorCount == 0 {
			merged.TensorCount = a.TensorCount
		}
		if merged.ShardCount == 0 {
			merged.ShardCount = a.ShardCount
		}
		firstNonEmpty(&merged.Parameters, a.Parameters)
		firstNonEmpty(&merged.TotalSize, a.TotalSize)
		firstNonEmpty(&merged.Architecture, a.Architecture)
		firstNonEmpty(&merged.Quantization, a.Quantization)
		firstNonEmpty(&merged.TorchDtype, a.TorchDtype)
		firstNonEmpty(&merged.TransformersVersion, a.TransformersVersion)
	}
}

// mergeShardsInto folds the per-shard header metadata into merged, returning
// the summed shard TensorCount and the list of non-empty per-shard hashes for
// the rollup. Architecture / TorchDtype / TransformersVersion are accepted as
// fallbacks if a shard ever carries them (the current parsers don't, but the
// resolver-backed enrichment runs afterwards and won't overwrite anything
// already set, so it's safe to populate them earlier).
func mergeShardsInto(merged *pkg.SafeTensorsModelInfo, shards []pkg.SafeTensorsModelInfo) (shardTensorTotal uint64, hashes []string) {
	seenKV := map[string]bool{}
	for _, s := range shards {
		shardTensorTotal += s.TensorCount
		firstNonEmpty(&merged.Quantization, s.Quantization)
		firstNonEmpty(&merged.Parameters, s.Parameters)
		firstNonEmpty(&merged.Architecture, s.Architecture)
		firstNonEmpty(&merged.TorchDtype, s.TorchDtype)
		firstNonEmpty(&merged.TransformersVersion, s.TransformersVersion)
		for _, kv := range s.UserMetadata {
			if seenKV[kv.Key] {
				continue
			}
			seenKV[kv.Key] = true
			merged.UserMetadata = append(merged.UserMetadata, kv)
		}
		if s.MetadataHash != "" {
			hashes = append(hashes, s.MetadataHash)
		}
	}
	return shardTensorTotal, hashes
}

func firstNonEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

// unionLocations gathers every location from every member into a single set.
func unionLocations(members []pkg.Package) file.LocationSet {
	out := file.NewLocationSet()
	for _, m := range members {
		for _, l := range m.Locations.ToSlice() {
			out.Add(l)
		}
	}
	return out
}

// bucketSafeTensorsMembers splits group members into aggregate-flavored entries
// (no MetadataHash — Docker AI config blob or sharded index) and shard-flavored
// entries (carry a content-derived MetadataHash from a header parser).
func bucketSafeTensorsMembers(members []pkg.Package) (aggregates, shards []pkg.SafeTensorsModelInfo) {
	for _, m := range members {
		md, ok := m.Metadata.(pkg.SafeTensorsModelInfo)
		if !ok {
			continue
		}
		if md.MetadataHash != "" {
			shards = append(shards, md)
			continue
		}
		aggregates = append(aggregates, md)
	}
	return aggregates, shards
}

// rollupHash returns a stable hash across the sorted set of per-member
// content-derived hashes. For a single member it returns that hash unchanged,
// so a single-file dir scan and an OCI scan with one safetensors layer surface
// the same value. For multi-shard models the rollup is the xxhash of the
// sorted hashes joined with "|".
func rollupHash(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}
	if len(hashes) == 1 {
		return hashes[0]
	}
	sorted := append([]string(nil), hashes...)
	sort.Strings(sorted)
	return fmt.Sprintf("%016x", xxhash.Sum64String(strings.Join(sorted, "|")))
}

// enrichSafeTensorsGroup reads the resolver once for the group to populate the
// merged metadata's Architecture / TorchDtype / TransformersVersion, set the
// licenses on the merged package, and attach the location of every consulted
// supporting file as SupportingEvidence. Returns the raw _name_or_path so the
// caller can apply path.Base in its naming step.
func enrichSafeTensorsGroup(ctx context.Context, resolver file.Resolver, groupKey string, merged *pkg.Package) (nameOrPath string) {
	md := merged.Metadata.(pkg.SafeTensorsModelInfo)

	var (
		lics       []pkg.License
		supporting []file.Location
	)
	if groupKey == ociGroupKey {
		nameOrPath, lics, supporting = enrichSafeTensorsOCI(ctx, resolver, &md)
	} else {
		nameOrPath, lics, supporting = enrichSafeTensorsDir(ctx, resolver, groupKey, &md)
	}

	merged.Metadata = md
	if len(lics) > 0 {
		merged.Licenses = pkg.NewLicenseSet(lics...)
	}
	for _, loc := range supporting {
		merged.Locations.Add(loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}
	return nameOrPath
}

// enrichSafeTensorsDir handles the directory-scan case: look for sibling
// config.json and README.md next to the model files.
func enrichSafeTensorsDir(ctx context.Context, resolver file.Resolver, dir string, md *pkg.SafeTensorsModelInfo) (nameOrPath string, lics []pkg.License, supporting []file.Location) {
	if loc, cfg := readDirHFConfig(resolver, path.Join(dir, "config.json")); cfg != nil {
		applyHFConfig(md, cfg)
		nameOrPath = cfg.NameOrPath
		supporting = append(supporting, *loc)
	}

	if loc, fm := readDirReadmeFrontmatter(resolver, path.Join(dir, "README.md")); fm != nil {
		if fm.License != "" {
			lics = pkg.NewLicensesFromValuesWithContext(ctx, fm.License)
		}
		if nameOrPath == "" && len(fm.BaseModel) > 0 {
			nameOrPath = fm.BaseModel[0]
		}
		supporting = append(supporting, *loc)
	}
	return nameOrPath, lics, supporting
}

// enrichSafeTensorsOCI handles the OCI-artifact case: walk the
// vnd.docker.ai.model.file layers (READMEs and HF config.json all ride that
// media type — we sniff content to tell them apart), then fall back to the
// vnd.docker.ai.license layer through the shared license scanner.
func enrichSafeTensorsOCI(ctx context.Context, resolver file.Resolver, md *pkg.SafeTensorsModelInfo) (nameOrPath string, lics []pkg.License, supporting []file.Location) {
	ociResolver, ok := resolver.(file.OCIMediaTypeResolver)
	if !ok {
		return "", nil, nil
	}

	modelFileLocs, err := ociResolver.FilesByMediaType(dockerAIModelFileMediaType)
	if err != nil {
		log.Debugf("failed to list docker AI model-file layers: %v", err)
	}

	// Collect config / readme candidates separately so the layer-iteration order
	// returned by the resolver doesn't decide the precedence.
	var configName, readmeName, readmeLicense string
	for _, loc := range modelFileLocs {
		if classifyOCIModelFileLayer(resolver, loc, md, &configName, &readmeName, &readmeLicense) {
			supporting = append(supporting, loc)
		}
	}

	// Precedence: config.json _name_or_path > README base_model.
	if configName != "" {
		nameOrPath = configName
	} else {
		nameOrPath = readmeName
	}

	// README license takes precedence; fall back to the license layer. For each
	// license layer we first try a cheap YAML-frontmatter spdx-id read; layers
	// without frontmatter fall through to the shared license scanner.
	switch {
	case readmeLicense != "":
		lics = pkg.NewLicensesFromValuesWithContext(ctx, readmeLicense)
	default:
		licLocs, lErr := ociResolver.FilesByMediaType(dockerAILicenseMediaType)
		if lErr != nil {
			log.Debugf("failed to list docker AI license layers: %v", lErr)
		}
		if len(licLocs) > 0 {
			lics = identifyLicenseLayers(ctx, resolver, licLocs)
			supporting = append(supporting, licLocs...)
		}
	}
	return nameOrPath, lics, supporting
}

// identifyLicenseLayers turns Docker AI license-layer locations into
// pkg.License values. It first attempts a cheap, exact SPDX-id read from the
// layer's YAML frontmatter (the choosealicense.com shape Docker Model Runner
// publishes for its AI artifacts); layers without frontmatter fall through to
// the shared license scanner. Each returned license is tagged with the layer
// location it came from so the SBOM cites its source.
func identifyLicenseLayers(ctx context.Context, resolver file.Resolver, locs []file.Location) []pkg.License {
	var out []pkg.License
	var scanFallback []file.Location
	for i := range locs {
		loc := locs[i]
		if spdx := readLicenseSPDXIDFromFrontmatter(resolver, loc); spdx != "" {
			out = append(out, pkg.NewLicenseFromFieldsWithContext(ctx, spdx, "", &loc))
			continue
		}
		scanFallback = append(scanFallback, loc)
	}
	if len(scanFallback) > 0 {
		out = append(out, licenses.FindAtLocations(ctx, resolver, scanFallback...)...)
	}
	return out
}

// readLicenseSPDXIDFromFrontmatter reads a bounded prefix of a license-layer
// blob and returns the spdx-id declared in its YAML frontmatter, if any. The
// 64 KiB cap is well above any real choosealicense.com frontmatter block while
// still bounding memory if the layer turns out to be huge.
func readLicenseSPDXIDFromFrontmatter(resolver file.Resolver, loc file.Location) string {
	rc, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return ""
	}
	defer internal.CloseAndLogError(rc, loc.RealPath)

	buf, err := io.ReadAll(io.LimitReader(rc, 64*1024))
	if err != nil {
		return ""
	}
	return parseLicenseFrontmatter(buf)
}

// classifyOCIModelFileLayer reads up to 4 MiB of a model.file layer and
// classifies it as README frontmatter or HF config.json based on its leading
// bytes. Side-effects: applies HF config fields onto md, accumulates name and
// license candidates via the out-params. Returns true when the layer was
// successfully classified (and should be recorded as supporting evidence).
func classifyOCIModelFileLayer(resolver file.Resolver, loc file.Location, md *pkg.SafeTensorsModelInfo, configName, readmeName, license *string) bool {
	rc, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return false
	}
	defer internal.CloseAndLogError(rc, loc.RealPath)

	buf, err := io.ReadAll(io.LimitReader(rc, 4*1024*1024))
	if err != nil {
		return false
	}
	trimmed := trimLeadingWhitespace(buf)
	switch {
	case hasPrefix(trimmed, "---"):
		fm := parseFrontmatter(buf)
		if fm == nil {
			return false
		}
		if *license == "" {
			*license = fm.License
		}
		if *readmeName == "" && len(fm.BaseModel) > 0 {
			*readmeName = fm.BaseModel[0]
		}
		return true
	case hasPrefix(trimmed, "{"):
		var cfg hfConfig
		if err := json.Unmarshal(buf, &cfg); err != nil {
			return false
		}
		applyHFConfig(md, &cfg)
		if *configName == "" && cfg.NameOrPath != "" {
			*configName = cfg.NameOrPath
		}
		return true
	}
	return false
}

// applyHFConfig folds the subset of HF config.json fields we surface in our
// metadata onto md. Fields already populated on md are left alone — earlier
// content-derived values (Quantization, TensorCount, etc., from header bytes)
// always win over producer-declared ones in case of conflict.
func applyHFConfig(md *pkg.SafeTensorsModelInfo, cfg *hfConfig) {
	if md.Architecture == "" && len(cfg.Architectures) > 0 {
		md.Architecture = cfg.Architectures[0]
	}
	if md.TorchDtype == "" {
		md.TorchDtype = cfg.TorchDtype
	}
	if md.TransformersVersion == "" {
		md.TransformersVersion = cfg.TransformersVersion
	}
}

// pickSafeTensorsName implements the documented naming precedence chain:
//
//  1. config.json _name_or_path             (path.Base, so "org/Model" → "Model")
//  2. OCI manifest title                    (deferred to a follow-up; reserved here)
//  3. Architecture-Parameters synthetic     (only when both are populated)
//  4. parent directory of the group         (dir-scan only — OCI has no useful path)
//
// Returns "" to signal the merge processor should drop the group rather than
// invent a name.
func pickSafeTensorsName(merged pkg.Package, groupKey, nameOrPath string) string {
	md, _ := merged.Metadata.(pkg.SafeTensorsModelInfo)

	if nameOrPath != "" {
		return path.Base(nameOrPath)
	}
	// 2. OCI manifest title — follow-up.

	if md.Architecture != "" && md.Parameters != "" {
		return md.Architecture + "-" + md.Parameters
	}

	if groupKey != ociGroupKey {
		base := path.Base(groupKey)
		if base != "" && base != "." && base != "/" {
			return base
		}
	}
	return ""
}

// --- Relocated enrichment helpers ----------------------------------------
//
// These types and functions used to live in the parser files; they moved here
// when the parsers shrank to "just decode the safetensors-specific format" and
// every resolver-backed read centralized in the merge processor.

// hfConfig is a minimal projection of Hugging Face config.json fields.
type hfConfig struct {
	Architectures       []string `json:"architectures"`
	TorchDtype          string   `json:"torch_dtype"`
	TransformersVersion string   `json:"transformers_version"`
	NameOrPath          string   `json:"_name_or_path"`
}

// readmeFrontmatter holds the subset of YAML frontmatter fields we extract.
type readmeFrontmatter struct {
	License   string   `yaml:"license"`
	BaseModel []string `yaml:"base_model"`
}

func readDirHFConfig(resolver file.Resolver, p string) (*file.Location, *hfConfig) {
	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return nil, nil
	}
	rc, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return nil, nil
	}
	defer internal.CloseAndLogError(rc, p)

	var cfg hfConfig
	if err := json.NewDecoder(rc).Decode(&cfg); err != nil {
		log.Debugf("failed to decode %s: %v", p, err)
		return nil, nil
	}
	return &locations[0], &cfg
}

func readDirReadmeFrontmatter(resolver file.Resolver, p string) (*file.Location, *readmeFrontmatter) {
	locations, err := resolver.FilesByPath(p)
	if err != nil || len(locations) == 0 {
		return nil, nil
	}
	rc, err := resolver.FileContentsByLocation(locations[0])
	if err != nil {
		return nil, nil
	}
	defer internal.CloseAndLogError(rc, p)

	buf, err := io.ReadAll(io.LimitReader(rc, 1024*1024))
	if err != nil {
		return nil, nil
	}
	fm := parseFrontmatter(buf)
	if fm == nil {
		return nil, nil
	}
	return &locations[0], fm
}

// extractFrontmatterBlock returns the YAML bytes between the first and second
// "---" delimiters of a file (stripping a leading BOM and any leading
// whitespace), or nil when no closed frontmatter block exists. Shared by every
// YAML-frontmatter parser the cataloger needs.
func extractFrontmatterBlock(buf []byte) []byte {
	trimmed := bytes.TrimLeft(buf, "\xef\xbb\xbf \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("---")) {
		return nil
	}
	rest := trimmed[3:]
	if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[i+1:]
	}
	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return nil
	}
	return rest[:end]
}

// parseFrontmatter decodes a Hugging Face model card YAML frontmatter block
// and returns the license and base_model fields. base_model is decoded via
// yaml.Node so a scalar value ("org/model") doesn't fail the whole block.
func parseFrontmatter(buf []byte) *readmeFrontmatter {
	block := extractFrontmatterBlock(buf)
	if block == nil {
		return nil
	}

	var raw struct {
		License   string    `yaml:"license"`
		BaseModel yaml.Node `yaml:"base_model"`
	}
	if err := yaml.Unmarshal(block, &raw); err != nil {
		log.Debugf("failed to parse README frontmatter: %v", err)
		return nil
	}

	fm := readmeFrontmatter{License: raw.License}
	switch raw.BaseModel.Kind {
	case yaml.ScalarNode:
		if raw.BaseModel.Value != "" {
			fm.BaseModel = []string{raw.BaseModel.Value}
		}
	case yaml.SequenceNode:
		_ = raw.BaseModel.Decode(&fm.BaseModel)
	}
	return &fm
}

// licenseFrontmatter holds the fields we lift from a choosealicense.com-style
// YAML frontmatter block at the top of a license file (the LICENSE blobs Docker
// Model Runner publishes for AI artifacts use this shape).
type licenseFrontmatter struct {
	SPDXID string `yaml:"spdx-id"`
}

// parseLicenseFrontmatter returns the producer-declared SPDX identifier from a
// choosealicense.com-style YAML frontmatter block, or "" if the buffer has no
// frontmatter or no spdx-id field — caller should fall back to a full license
// scan in that case.
func parseLicenseFrontmatter(buf []byte) string {
	block := extractFrontmatterBlock(buf)
	if block == nil {
		return ""
	}
	var fm licenseFrontmatter
	if err := yaml.Unmarshal(block, &fm); err != nil {
		log.Debugf("failed to parse license frontmatter: %v", err)
		return ""
	}
	return fm.SPDXID
}

func hasPrefix(b []byte, s string) bool {
	return len(b) >= len(s) && string(b[:len(s)]) == s
}

func trimLeadingWhitespace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n') {
		i++
	}
	if len(b)-i >= 3 && b[i] == 0xEF && b[i+1] == 0xBB && b[i+2] == 0xBF {
		i += 3
	}
	return b[i:]
}
