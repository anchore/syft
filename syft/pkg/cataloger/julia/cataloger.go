/*
Package julia provides a concrete Cataloger implementation for packages relating to the Julia language ecosystem.
*/
package julia

import (
	"path"
	"sort"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

const (
	runtimeKind  = "runtime"
	testKind     = "test"
	optionalKind = "optional"
)

type juliaPackageKey struct {
	projectDir string
	uuid       string
	version    string
}

func NewPackageCataloger(cfg CatalogerConfig) pkg.Cataloger {
	parser := newManifestParser(cfg)
	return generic.NewCataloger("julia-manifest-cataloger").
		WithParserByGlobs(parser.parseManifest, "**/Manifest.toml", "**/Manifest-v*.toml").
		WithProcessors(deduplicateJuliaManifestPackages)
}

func deduplicateJuliaManifestPackages(pkgs []pkg.Package, _ []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	var out []pkg.Package
	seen := make(map[juliaPackageKey]int)

	for _, p := range pkgs {
		meta, ok := p.Metadata.(pkg.JuliaManifestEntry)
		if !ok {
			out = append(out, p)
			continue
		}

		key := juliaPackageKey{
			projectDir: packageProjectDir(p),
			uuid:       meta.UUID,
			version:    p.Version,
		}
		if idx, ok := seen[key]; ok {
			mergeJuliaManifestPackage(&out[idx], p)
			continue
		}

		seen[key] = len(out)
		out = append(out, p)
	}

	pkg.Sort(out)
	return out, dependency.Resolve(juliaManifestDependencySpecifier, out), err
}

func packageProjectDir(p pkg.Package) string {
	locations := p.Locations.ToSlice()
	if len(locations) == 0 {
		return ""
	}
	return path.Dir(locations[0].RealPath)
}

func mergeJuliaManifestPackage(dst *pkg.Package, src pkg.Package) {
	dst.Locations.Add(src.Locations.ToSlice()...)

	dstMeta, dstOK := dst.Metadata.(pkg.JuliaManifestEntry)
	srcMeta, srcOK := src.Metadata.(pkg.JuliaManifestEntry)
	if !dstOK || !srcOK {
		dst.SetID()
		return
	}

	dstMeta.Deps = mergeStrings(dstMeta.Deps, srcMeta.Deps)
	if dstMeta.Path == "" {
		dstMeta.Path = srcMeta.Path
	}
	dstMeta.DependencyKind = mergeDependencyKind(dstMeta.DependencyKind, srcMeta.DependencyKind)
	dst.Metadata = dstMeta
	dst.SetID()
}

func mergeStrings(values ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, value := range values {
		for _, item := range value {
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func mergeDependencyKind(a, b string) string {
	if dependencyKindRank(b) > dependencyKindRank(a) {
		return b
	}
	return a
}

func dependencyKindRank(kind string) int {
	switch kind {
	case runtimeKind:
		return 3
	case testKind:
		return 2
	case optionalKind:
		return 1
	default:
		return 0
	}
}
