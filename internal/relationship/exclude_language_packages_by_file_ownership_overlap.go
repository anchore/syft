package relationship

import (
	"slices"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var (
	// languageCatalogerTypes are package types that an OS package can legitimately subsume when it
	// owns their files: language packages installed as discrete units (one package == its own files),
	// for which OS file-ownership overlap means the distro repackaged the same thing.
	//
	// Inclusion rule (enforced by Test_languageCatalogerTypes_matchesLanguageTag, derived from
	// cataloger capabilities so new catalogers stay covered):
	//   languageCatalogerTypes == {types of "language"-tagged catalogers} \ osCatalogerTypes
	//                             \ binaryExtractedLanguageTypes  (+ documented exceptions)
	//
	// Deliberately EXCLUDED are types whose catalogers extract many components from a single artifact the
	// OS package owns (a binary or fat archive): go-module (GoModulePkg), rust-crate (RustPkg),
	// dotnet (DotnetPkg), graalvm-native-image (GraalVMNativeImagePkg) and java-archive (JavaPkg). OS
	// ownership of that container does NOT make the embedded components redundant — they have distinct
	// identities/versions/PURLs/licenses and must stay in the SBOM (an rpm owning /usr/bin/foo must not
	// delete the Go modules built into foo). The exclusion set lives in the test as
	// binaryExtractedLanguageTypes and is verified against cataloger capabilities.
	//
	// Known limitation: this rule keys on pkg.Type, a coarse proxy. A more precise rule would key on
	// per-package evidence (subsume only packages found as discrete installed artifacts, not
	// manifest/lockfile-declared ones), since some included types can also be lockfile-derived. Kept at
	// the type level to match the existing binary-overlap exclusion; tracked as a follow-up.
	languageCatalogerTypes = []pkg.Type{
		pkg.CocoapodsPkg,
		pkg.ConanPkg,
		pkg.DartPubPkg,
		pkg.ErlangOTPPkg,
		pkg.GemPkg,
		pkg.HackagePkg,
		pkg.HexPkg,
		pkg.LuaRocksPkg,
		pkg.NpmPkg,
		pkg.OpamPkg,
		pkg.PhpComposerPkg,
		pkg.PhpPearPkg,
		pkg.PhpPeclPkg, // exception: php-pecl cataloger is DeprecatedTag (untagged for language); kept until removed in syft v2.0
		pkg.PythonPkg,
		pkg.Rpkg,
		pkg.SwiftPkg,
		pkg.SwiplPackPkg,
	}
)

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

	if slices.Contains(languageCatalogerTypes, child.Type) {
		return child.ID()
	}

	return ""
}
