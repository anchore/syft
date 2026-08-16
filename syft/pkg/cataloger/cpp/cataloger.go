/*
Package cpp provides a concrete Cataloger implementations for the C/C++ language ecosystem.
*/
package cpp

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewConanCataloger returns a new C/C++ conanfile.txt and conan.lock cataloger object.
func NewConanCataloger() pkg.Cataloger {
	return generic.NewCataloger("conan-cataloger").
		WithParserByGlobs(parseConanfile, "**/conanfile.txt").
		WithParserByGlobs(parseConanLock, "**/conan.lock")
}

// NewConanInfoCataloger returns a new C/C++ conaninfo.txt cataloger object.
func NewConanInfoCataloger() pkg.Cataloger {
	return generic.NewCataloger("conan-info-cataloger").
		WithParserByGlobs(parseConaninfo, "**/conaninfo.txt")
}

// vcpkg (the Microsoft C/C++ package manager) has two modes
// (https://learn.microsoft.com/en-us/vcpkg/concepts/classic-mode):
//   - classic mode: `vcpkg install <pkg>` populates a central tree at $VCPKG_ROOT/installed/.
//   - manifest mode: a vcpkg.json declares dependencies; after a build the resolved tree appears
//     under vcpkg_installed/ (a vcpkg/status DB + per-triplet dirs).
//
// what is on disk depends on where in the lifecycle the scan happens:
//   - source checkout (the dir-scan case): vcpkg.json (+ vcpkg-configuration.json, overlay ports)
//     are present. vcpkg_installed/ is a build artifact and is gitignored, so it is NOT present;
//     exact transitive versions live in the registry, not the manifest.
//   - built artifact: vcpkg_installed/ holds the actually-installed truth.
//
// NewVcpkgManifestCataloger covers ONLY the manifest (dir/source) case: it reads vcpkg.json and its
// declared dependencies and resolves each dependency's manifest from the vcpkg registry. resolving the
// registry needs a local registry clone or a network clone, which is opt-in via
// CatalogerConfig.VcpkgAllowGitClone (wired to --enrich).
//
// it deliberately does NOT cover installed state: vcpkg_installed/ (vcpkg/status, per-package
// vcpkg.spdx.json, copyright, ABI info), the build triplet (a build-time choice recorded only under
// vcpkg_installed/), and classic-mode central installs.
//
// why there is no installed-state (vcpkg/status) cataloger yet: vcpkg_installed/ tends to be a gitignored
// build artifact, so whether it survives into a scannable target is pattern-dependent. it is dropped by slim
// multi-stage runtime images (the documented best practice copies only the app binary / binary cache
// between stages) and by dev/base images (which bootstrap the tool, not packages); no canonical public
// image ships a populated vcpkg/status by default. it is retained mainly in single-stage builder / CI /
// "fat" app images. so a status-based cataloger has real but not universal payoff and is deferred until
// it is worth the maintenance.
func NewVcpkgManifestCataloger(opts CatalogerConfig) pkg.Cataloger {
	return generic.NewCataloger("vcpkg-manifest-cataloger").WithParserByGlobs(newVcpkgCataloger(opts.VcpkgAllowGitClone).parseVcpkgManifest, "**/vcpkg.json")
}
