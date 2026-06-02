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
	gcrname "github.com/google/go-containerregistry/pkg/name"
	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/licenses"
)

// ociGroupKey is the grouping key for every safetensors package that
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

// safeTensorsMergeProcessor owns naming, license resolution, and tensor package creation
// - groups all nameless packages
// - merge the per-shard metadata
// - picks a name (see pickSafeTensorsName)
func safeTensorsMergeProcessor(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil || len(pkgs) == 0 {
		return pkgs, rels, err
	}

	// split off non-safetensors packages
	// this keeps the processor robust if other types ever flow through
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

		// Resolve model identity (name candidates) before enrich
		id := resolveSafeTensorsIdentity(resolver, key, &merged)
		name := pickSafeTensorsName(id.nameOrPath, id.fallbackName)
		if name == "" {
			log.Debugf("dropped safetensors model package (metadata hash %q): no name source",
				merged.Metadata.(pkg.SafeTensorsModelInfo).MetadataHash)
			continue
		}

		enrichSafeTensorsGroup(ctx, resolver, key, &merged, id)
		merged.Name = name
		merged.SetID()
		out = append(out, merged)
	}
	return out, rels, nil
}

// groupSafeTensorsPackages buckets packages by the parent directory of their
// primary-evidence location
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

// mergeSafeTensorsGroup folds a group's per-member metadata into a single package.
func mergeSafeTensorsGroup(members []pkg.Package) pkg.Package {
	locSet := unionLocations(members)
	aggregates, shards := bucketSafeTensorsMembers(members)

	merged := pkg.SafeTensorsModelInfo{Format: "safetensors"}
	mergeAggregatesInto(&merged, aggregates)
	shardTensorTotal, hashes := mergeShardsInto(&merged, shards)

	// Keep merged UserMetadata globally key-sorted so the SBOM is stable
	sort.Slice(merged.UserMetadata, func(i, j int) bool {
		return merged.UserMetadata[i].Key < merged.UserMetadata[j].Key
	})

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
		firstNonEmpty(&merged.Quantization, a.Quantization)
	}
}

// mergeShardsInto folds the per-shard header metadata into merged, returning
// the summed shard TensorCount and the list of non-empty per-shard hashes for
// the rollup. Shards carry only the content-derived fields (Quantization,
// Parameters, UserMetadata);
func mergeShardsInto(merged *pkg.SafeTensorsModelInfo, shards []pkg.SafeTensorsModelInfo) (shardTensorTotal uint64, hashes []string) {
	seenKV := map[string]bool{}
	for _, s := range shards {
		shardTensorTotal += s.TensorCount
		firstNonEmpty(&merged.Quantization, s.Quantization)
		firstNonEmpty(&merged.Parameters, s.Parameters)
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

type safeTensorsIdentity struct {
	nameOrPath    string
	fallbackName  string
	readmeLicense string
	supporting    []file.Location
}

// resolveSafeTensorsIdentity reads the resolver for the group's naming signals
// (config.json _name_or_path, README base_model, OCI image ref / dir name)
func resolveSafeTensorsIdentity(resolver file.Resolver, groupKey string, merged *pkg.Package) safeTensorsIdentity {
	md := merged.Metadata.(pkg.SafeTensorsModelInfo)

	var id safeTensorsIdentity
	if groupKey == ociGroupKey {
		id = resolveSafeTensorsOCIIdentity(resolver, &md)
	} else {
		id = resolveSafeTensorsDirIdentity(resolver, groupKey, &md)
	}

	merged.Metadata = md
	return id
}

func enrichSafeTensorsGroup(ctx context.Context, resolver file.Resolver, groupKey string, merged *pkg.Package, id safeTensorsIdentity) {
	var lics []pkg.License
	supporting := id.supporting

	switch {
	case id.readmeLicense != "":
		lics = pkg.NewLicensesFromValuesWithContext(ctx, id.readmeLicense)
	case groupKey == ociGroupKey:
		if ociResolver, ok := resolver.(file.OCIMediaTypeResolver); ok {
			licLocs, err := ociResolver.FilesByMediaType(dockerAILicenseMediaType)
			if err != nil {
				log.Debugf("failed to list docker AI license layers: %v", err)
			}
			if len(licLocs) > 0 {
				lics = identifyLicenseLayers(ctx, resolver, licLocs)
				supporting = append(supporting, licLocs...)
			}
		}
	}

	if len(lics) > 0 {
		merged.Licenses = pkg.NewLicenseSet(lics...)
	}
	for _, loc := range supporting {
		merged.Locations.Add(loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}
}

// safeTensorsDirName returns the directory-scan naming fallback: the base name
// of the group's parent directory (the group key is already that directory).
func safeTensorsDirName(groupKey string) string {
	base := path.Base(groupKey)
	switch base {
	case "/", ".", "":
		return ""
	}
	return base
}

// resolveSafeTensorsDirIdentity handles the directory-scan case: look for a
// config.json beside the model files (walking up parent directories to the
// scanned source root if no sibling exists) and a sibling README.md
func resolveSafeTensorsDirIdentity(resolver file.Resolver, dir string, md *pkg.SafeTensorsModelInfo) safeTensorsIdentity {
	id := safeTensorsIdentity{fallbackName: safeTensorsDirName(dir)}

	if loc, cfg := findDirHFConfig(resolver, dir); cfg != nil {
		applyHFConfig(md, cfg)
		id.nameOrPath = cfg.NameOrPath
		id.supporting = append(id.supporting, *loc)
	}

	if loc, fm := readDirReadmeFrontmatter(resolver, path.Join(dir, "README.md")); fm != nil {
		id.readmeLicense = fm.License
		if id.nameOrPath == "" && len(fm.BaseModel) > 0 {
			id.nameOrPath = fm.BaseModel[0]
		}
		id.supporting = append(id.supporting, *loc)
	}
	return id
}

func resolveSafeTensorsOCIIdentity(resolver file.Resolver, md *pkg.SafeTensorsModelInfo) safeTensorsIdentity {
	ociResolver, ok := resolver.(file.OCIMediaTypeResolver)
	if !ok {
		return safeTensorsIdentity{}
	}

	modelFileLocs, err := ociResolver.FilesByMediaType(dockerAIModelFileMediaType)
	if err != nil {
		log.Debugf("failed to list docker AI model-file layers: %v", err)
	}

	// Collect config / readme candidates separately so the layer-iteration order
	// returned by the resolver doesn't decide the precedence.
	var configName, readmeName, readmeLicense string
	var supporting []file.Location
	for _, loc := range modelFileLocs {
		if classifyOCIModelFileLayer(resolver, loc, md, &configName, &readmeName, &readmeLicense) {
			supporting = append(supporting, loc)
		}
	}

	// Precedence: config.json _name_or_path > README base_model.
	nameOrPath := configName
	if nameOrPath == "" {
		nameOrPath = readmeName
	}

	return safeTensorsIdentity{
		nameOrPath:    nameOrPath,
		fallbackName:  ociImageRefBasename(resolver),
		readmeLicense: readmeLicense,
		supporting:    supporting,
	}
}

func ociImageRefBasename(resolver file.Resolver) string {
	// TODO: we don't think this approach is generalizable quite yet, but we really do need this information.
	// (Ideally we should be NOT be type asserting on the file resolver directly).
	info, ok := resolver.(*fileresolver.ContainerImageModel)
	if !ok {
		return ""
	}
	ref := info.ImageReference()
	if ref == "" {
		return ""
	}
	parsed, err := gcrname.ParseReference(ref)
	if err != nil {
		log.Debugf("failed to parse OCI ref %q: %v", ref, err)
		return ""
	}
	return path.Base(parsed.Context().RepositoryStr())
}

// identifyLicenseLayers turns Docker AI license-layer locations into
// pkg.License values.
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
// blob and returns the spdx-id declared in its YAML frontmatter
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
// classifies it as README frontmatter or HF config.json based on its leading bytes.
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
	trimmed := bytes.TrimLeft(buf, "\xef\xbb\xbf \t\r\n")
	switch {
	case bytes.HasPrefix(trimmed, []byte("---")):
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
	case bytes.HasPrefix(trimmed, []byte("{")):
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

func applyHFConfig(md *pkg.SafeTensorsModelInfo, cfg *hfConfig) {
	if md.Architecture == "" && len(cfg.Architectures) > 0 {
		md.Architecture = cfg.Architectures[0]
	}
}

// pickSafeTensorsName implements the documented naming precedence chain:
//   - config.json _name_or_path  (path.Base, so "org/Model" → "Model";
//     applies to both dir-scan and OCI groups)
//   - fallback name — the group's source-specific positional identifier
func pickSafeTensorsName(nameOrPath, fallbackName string) string {
	if nameOrPath != "" {
		return path.Base(nameOrPath)
	}
	return fallbackName
}

// hfConfig is a minimal projection of Hugging Face config.json fields.
type hfConfig struct {
	Architectures []string `json:"architectures"`
	NameOrPath    string   `json:"_name_or_path"`
}

// readmeFrontmatter holds the subset of YAML frontmatter fields we extract.
type readmeFrontmatter struct {
	License   string   `yaml:"license"`
	BaseModel []string `yaml:"base_model"`
}

// findDirHFConfig looks for a config.json beside the model files
func findDirHFConfig(resolver file.Resolver, dir string) (*file.Location, *hfConfig) {
	for {
		if loc, cfg := readDirHFConfig(resolver, path.Join(dir, "config.json")); cfg != nil {
			return loc, cfg
		}
		parent := path.Dir(dir)
		if parent == dir {
			return nil, nil // reached the source root
		}
		dir = parent
	}
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
// "---" delimiters of a file
func extractFrontmatterBlock(buf []byte) []byte {
	trimmed := bytes.TrimLeft(buf, "\xef\xbb\xbf \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("---")) {
		return nil
	}
	rest := trimmed[3:]
	if i := bytes.IndexByte(rest, '\n'); i >= 0 {
		rest = rest[i+1:]
	}
	block, _, found := bytes.Cut(rest, []byte("\n---"))
	if !found {
		return nil
	}
	return block
}

// parseFrontmatter decodes a Hugging Face model card YAML frontmatter block
// and returns the license and base_model fields.
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

type licenseFrontmatter struct {
	SPDXID string `yaml:"spdx-id"`
}

// parseLicenseFrontmatter returns the producer-declared SPDX identifier
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
