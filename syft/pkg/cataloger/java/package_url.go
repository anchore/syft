package java

import (
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

// PackageURL returns the PURL for the specific java package (see https://github.com/package-url/purl-spec)
func packageURL(name, version string, metadata pkg.JavaMetadata) string {
	groupID := cpe.GroupIDFromJavaMetadata(metadata)
	if groupID == "" {
		// we could not find the group ID in the pom xml, pom properties, or manifest
		// last ditch use the name for cases like this
		// https://mvnrepository.com/artifact/postgresql/postgresql/9.1-901-1.jdbc4
		groupID = name
	}
	pURL := packageurl.NewPackageURL(
		packageurl.TypeMaven, // TODO: should we filter down by package types here?
		groupID,
		name,
		version,
		nil, // TODO: there are probably several qualifiers that can be specified here
		"")
	return pURL.ToString()
}
