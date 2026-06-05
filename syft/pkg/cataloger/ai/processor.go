package ai

import (
	"context"
	"path"
	"sort"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// safeTensorsMergeProcessor owns naming, license resolution, and final package
// assembly. SafeTensors packages reach it nameless from the parsers; it groups
// them per model, merges the per-shard metadata, resolves a name + licenses, and
// drops any model it cannot name.
func safeTensorsMergeProcessor(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	if err != nil || len(pkgs) == 0 {
		return pkgs, rels, err
	}

	// keep the processor robust if non-safetensors packages ever flow through
	stPkgs, other := partitionSafeTensorsPackages(pkgs)
	if len(stPkgs) == 0 {
		return pkgs, rels, err
	}

	if fromOCIArtifact(stPkgs) {
		return append(other, mergeOCIModel(ctx, resolver, stPkgs)...), rels, nil
	}
	return append(other, mergeDirModels(ctx, resolver, stPkgs)...), rels, nil
}

// partitionSafeTensorsPackages separates safetensors packages from anything else
// flowing through the processor.
func partitionSafeTensorsPackages(pkgs []pkg.Package) (safeTensors, other []pkg.Package) {
	for _, p := range pkgs {
		if _, ok := p.Metadata.(pkg.SafeTensorsModelInfo); ok {
			safeTensors = append(safeTensors, p)
			continue
		}
		other = append(other, p)
	}
	return safeTensors, other
}

// fromOCIArtifact reports whether the packages came from an OCI model artifact.
// That source (the ContainerImageModel resolver) presents every layer at the
// virtual path "/", whereas a filesystem scan always carries a real file path. A
// single scan is one source, so the first package is representative of the rest.
func fromOCIArtifact(pkgs []pkg.Package) bool {
	loc := primaryEvidenceLocation(pkgs[0])
	return loc != nil && loc.RealPath == "/"
}

// mergeOCIModel treats the whole OCI artifact as a single model: every layer
// merges into one package, named from the artifact's config.json/README or its
// image reference.
func mergeOCIModel(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package) []pkg.Package {
	merged := mergeSafeTensorsGroup(pkgs)

	md := merged.Metadata.(pkg.SafeTensorsModelInfo)
	id := resolveSafeTensorsOCIIdentity(ctx, resolver, &md)
	merged.Metadata = md // write architecture enrichment back before assembly

	if p, ok := assembleSafeTensorsPackage(merged, id); ok {
		return []pkg.Package{p}
	}
	return nil
}

// mergeDirModels groups filesystem-scanned files by their parent directory and
// emits one model per directory
func mergeDirModels(ctx context.Context, resolver file.Resolver, pkgs []pkg.Package) []pkg.Package {
	groups := groupByParentDir(pkgs)

	// deterministic iteration order so the SBOM doesn't depend on map order
	dirs := make([]string, 0, len(groups))
	for dir := range groups {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	var out []pkg.Package
	for _, dir := range dirs {
		merged := mergeSafeTensorsGroup(groups[dir])

		md := merged.Metadata.(pkg.SafeTensorsModelInfo)
		id := resolveSafeTensorsDirIdentity(ctx, resolver, dir, &md)
		merged.Metadata = md // write architecture enrichment back before assembly

		if p, ok := assembleSafeTensorsPackage(merged, id); ok {
			out = append(out, p)
		}
	}
	return out
}

// groupByParentDir buckets filesystem-scanned packages by the directory their
// primary-evidence file lives in (the shards of one model share a directory).
func groupByParentDir(pkgs []pkg.Package) map[string][]pkg.Package {
	out := make(map[string][]pkg.Package)
	for _, p := range pkgs {
		loc := primaryEvidenceLocation(p)
		if loc == nil {
			continue
		}
		dir := path.Dir(loc.RealPath)
		out[dir] = append(out[dir], p)
	}
	return out
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

// safeTensorsIdentity is the fully-resolved naming/license result for a model.
// Each source resolver (dir or OCI) populates it so assembly stays source-agnostic.
type safeTensorsIdentity struct {
	nameOrPath   string
	fallbackName string
	licenses     []pkg.License
	supporting   []file.Location
}

// assembleSafeTensorsPackage finalizes a merged model from its resolved identity:
// it picks the name, attaches licenses and supporting evidence, and sets the ID.
// A model with no name source is dropped (ok=false).
func assembleSafeTensorsPackage(merged pkg.Package, id safeTensorsIdentity) (pkg.Package, bool) {
	name := pickSafeTensorsName(id.nameOrPath, id.fallbackName)
	if name == "" {
		log.Debugf("dropped safetensors model package (metadata hash %q): no name source",
			merged.Metadata.(pkg.SafeTensorsModelInfo).MetadataHash)
		return pkg.Package{}, false
	}

	if len(id.licenses) > 0 {
		merged.Licenses = pkg.NewLicenseSet(id.licenses...)
	}
	for _, loc := range id.supporting {
		merged.Locations.Add(loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
	}

	merged.Name = name
	merged.SetID()
	return merged, true
}
