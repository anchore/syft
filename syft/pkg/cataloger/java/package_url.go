package java

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

// PackageURL returns the PURL for the specific java package (see https://github.com/package-url/purl-spec)
func packageURL(p pkg.Package) string {
	var groupID = p.Name
	groupIDs := cpe.GroupIDsFromJavaPackage(p)
	if len(groupIDs) > 0 {
		groupID = groupIDs[0]
	}

	pURL := packageurl.NewPackageURL(
		packageurl.TypeMaven, // TODO: should we filter down by package types here?
		groupID,
		p.Name,
		p.Version,
		nil, // TODO: there are probably several qualifiers that can be specified here
		"")
	return pURL.ToString()
}
