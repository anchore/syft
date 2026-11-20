package helpers

import (
	"fmt"
	"net/url"
	"strings"

	urilib "github.com/spdx/gordf/uri"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/anchore/syft/syft/pkg"
)

const NONE = "NONE"
const NOASSERTION = "NOASSERTION"
const SUPPLIERORG = "Organization"

// goProxy is the public Go module proxy used to construct a stable, publicly
// resolvable download location for Go modules.
const goProxy = "https://proxy.golang.org"

// golangStdlib is the synthetic package name syft assigns to the Go standard
// library, which is not a downloadable module.
const golangStdlib = "stdlib"

func DownloadLocation(p pkg.Package) string {
	// 3.7: Package Download Location
	// Cardinality: mandatory, one
	// NONE if there is no download location whatsoever.
	// NOASSERTION if:
	//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
	//   (ii) the SPDX file creator has made no attempt to determine this field; or
	//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).

	var location string
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.ApkDBEntry:
			location = metadata.URL
		case pkg.NpmPackage:
			location = metadata.URL
		case pkg.NpmPackageLockEntry:
			location = metadata.Resolved
		case pkg.PhpComposerLockEntry:
			location = metadata.Dist.URL
		case pkg.PhpComposerInstalledEntry:
			location = metadata.Dist.URL
		case pkg.OpamPackage:
			location = metadata.URL
		case pkg.GolangBinaryBuildinfoEntry, pkg.GolangModuleEntry, pkg.GolangSourceEntry:
			location = golangProxyLocation(p.Name, p.Version)
		}
	}
	return URIValue(location)
}

// golangProxyLocation builds the Go module proxy download URL for a module
// version, or returns an empty string when the package is not a downloadable
// module (the standard library, or a version that is not a module version such
// as "(devel)" or a bare Go toolchain version).
func golangProxyLocation(name, version string) string {
	if name == golangStdlib || !semver.IsValid(version) {
		return ""
	}
	escapedPath, err := module.EscapePath(name)
	if err != nil {
		return ""
	}
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s/%s/@v/%s.zip", goProxy, escapedPath, escapedVersion)
}

func isURIValid(uri string) bool {
	_, err := urilib.NewURIRef(uri)
	return err == nil
}

func URIValue(uri string) string {
	if strings.ToLower(uri) != "none" {
		if isURIValid(uri) {
			return updateForGithub(url.Parse(uri))
		}
		return NOASSERTION
	}
	return NONE
}

// Github repository is a valid NPM location but not a valid SPDX DownloadURL
func updateForGithub(uri *url.URL, err error) string {
	if err != nil {
		return NOASSERTION
	}
	updatedLocation := uri.String()
	if uri.Scheme == "github" {
		updatedLocation = "https://github.com/" + uri.Opaque
	}
	return updatedLocation
}
