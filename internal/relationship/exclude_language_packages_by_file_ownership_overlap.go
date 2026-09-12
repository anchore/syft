package relationship

import (
	"slices"
	"sync"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"

	// register the embedded cataloger capability files that languageCatalogerTypes derives from;
	// without this import, consumers that never link syft/pkg/cataloger (library use) would derive
	// an empty set and the exclusion would silently do nothing
	_ "github.com/anchore/syft/syft/pkg/cataloger"
)

// binaryExtractedLanguageTypes are language types whose packages are components extracted from a single
// OS-owned binary or fat archive. Deleting them on OS file ownership would drop distinct components
// (with their own identities, versions, PURLs and licenses) that the OS package does not replace: an rpm
// owning /usr/bin/foo must not delete the Go modules built into foo.
//
// This is an explicit list rather than a set derived from the "binary" cataloger selector, because the
// selector does not decide the question: several types are emitted by both an extractor and a
// discrete-unit cataloger (npm by dotnet-deps-binary-cataloger and javascript-package-cataloger,
// go-module by go-module-binary-cataloger and go-module-file-cataloger), and which emitter dominates in
// practice is not recorded in the capability data.
var binaryExtractedLanguageTypes = []pkg.Type{
	pkg.GoModulePkg,           // modules built into a binary
	pkg.RustPkg,               // crates built into a binary
	pkg.DotnetPkg,             // deps of a .NET binary
	pkg.GraalVMNativeImagePkg, // SBOM embedded in a native image
	pkg.JavaPkg,               // (nested) JARs inside an OS-owned archive
}

// languageTypeExceptions are types included even though no "language"-tagged cataloger emits them.
var languageTypeExceptions = map[pkg.Type]string{
	// php-pecl is emitted only by the deprecated (DeprecatedTag, not language-tagged) pecl cataloger;
	// its packages still overlap OS packages until the cataloger is removed in syft v2.0.
	pkg.PhpPeclPkg: "deprecated php-pecl cataloger (not language-tagged)",
}

// languageCatalogerTypes returns the package types an OS package can subsume when it owns their files:
// language packages installed as discrete units, for which OS file-ownership overlap means the distro
// repackaged the same thing. The set is derived from syft's own cataloger capabilities so that
// catalogers added later are covered without touching this file:
//
//	{types of "language"-tagged catalogers} \ osCatalogerTypes \ binaryExtractedLanguageTypes
//	                                        (+ languageTypeExceptions)
//
// This keys on pkg.Type, a coarse proxy; a per-package rule (installed vs manifest-declared evidence)
// is tracked in https://github.com/anchore/syft/issues/4974.
//
// The capability files are compiled in via go:embed and registered by the blank import above, so a
// failed derivation indicates a build problem. In that case exclude nothing (warned once): dropping
// packages from the SBOM on incomplete information is the worse failure.
var languageCatalogerTypes = sync.OnceValue(deriveLanguageCatalogerTypes)

func deriveLanguageCatalogerTypes() map[pkg.Type]struct{} {
	catalogers, err := capabilities.Packages()
	if err != nil {
		log.WithFields("error", err).Warn("unable to load cataloger capabilities; exclude-language-packages-with-file-ownership-overlap will not exclude anything")
		return nil
	}

	osTypes := strset.New()
	for _, ty := range osCatalogerTypes {
		osTypes.Add(string(ty))
	}

	extracted := strset.New()
	for _, ty := range binaryExtractedLanguageTypes {
		extracted.Add(string(ty))
	}

	included := strset.New()
	for _, c := range catalogers {
		if !slices.Contains(c.Selectors, "language") {
			continue
		}
		included.Add(catalogerPackageTypes(c)...)
	}

	out := make(map[pkg.Type]struct{})
	for _, pt := range included.List() {
		if osTypes.Has(pt) || extracted.Has(pt) {
			continue
		}
		out[pkg.Type(pt)] = struct{}{}
	}
	for ty := range languageTypeExceptions {
		out[ty] = struct{}{}
	}

	return out
}

// catalogerPackageTypes collects the package types a cataloger emits, from the entry and its parsers.
func catalogerPackageTypes(c capabilities.CatalogerEntry) []string {
	pts := append([]string{}, c.PackageTypes...)
	for _, p := range c.Parsers {
		pts = append(pts, p.PackageTypes...)
	}
	return pts
}

func ExcludeLanguagePackagesByFileOwnershipOverlap(accessor sbomsync.Accessor) {
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		for _, r := range s.Relationships {
			if idToRemove := excludeLanguagePackageByFileOwnershipOverlap(r, s.Artifacts.Packages); idToRemove != "" {
				s.Artifacts.Packages.Delete(idToRemove)
				s.Relationships = RemoveRelationshipsByID(s.Relationships, idToRemove)
			}
		}
	})
}

// excludeLanguagePackageByFileOwnershipOverlap will remove language packages that are owned by OS packages.
// This was implemented as a way to help resolve: https://github.com/anchore/syft/issues/4760
func excludeLanguagePackageByFileOwnershipOverlap(r artifact.Relationship, c *pkg.Collection) artifact.ID {
	if artifact.OwnershipByFileOverlapRelationship != r.Type {
		return ""
	}

	parent := c.Package(r.From.ID())
	if parent == nil {
		return ""
	}

	child := c.Package(r.To.ID())
	if child == nil {
		return ""
	}

	return identifyOverlappingLanguageRelationship(parent, child)
}

// identifyOverlappingLanguageRelationship indicates the package ID to remove if this is an OS pkg -> language pkg relationship.
func identifyOverlappingLanguageRelationship(parent *pkg.Package, child *pkg.Package) artifact.ID {
	if !slices.Contains(osCatalogerTypes, parent.Type) {
		return ""
	}

	if _, ok := languageCatalogerTypes()[child.Type]; ok {
		return child.ID()
	}

	return ""
}
