package cataloger

import (
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/package-url/packageurl-go"
)

// generatePackageURL returns a package-URL representation of the given package (see https://github.com/package-url/purl-spec)
func generatePackageURL(p pkg.Package, d *distro.Distro) string {
	// default to pURLs on the metadata
	if p.Metadata != nil {
		if i, ok := p.Metadata.(interface{ PackageURL() string }); ok {
			return i.PackageURL()
		} else if i, ok := p.Metadata.(interface{ PackageURL(*distro.Distro) string }); ok {
			return i.PackageURL(d)
		}
	}

	var purlType = p.Type.PackageURLType()
	var name = p.Name
	var namespace = ""

	switch {
	case purlType == "":
		// there is no purl type, don't attempt to craft a purl
		// TODO: should this be a "generic" purl type instead?
		return ""
	case p.Type == pkg.GoModulePkg:
		re := regexp.MustCompile(`(/)[^/]*$`)
		fields := re.Split(p.Name, -1)
		namespace = fields[0]
		name = strings.TrimPrefix(p.Name, namespace+"/")
	}

	// generate a purl from the package data
	pURL := packageurl.NewPackageURL(
		purlType,
		namespace,
		name,
		p.Version,
		nil,
		"")

	return pURL.ToString()
}
