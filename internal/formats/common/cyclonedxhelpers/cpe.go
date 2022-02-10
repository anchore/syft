package cyclonedxhelpers

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

func encodeCPE(p pkg.Package) string {
	// Since the CPEs in a package are sorted by specificity
	// we can extract the first encodeCPE as the one to output in cyclonedx
	if len(p.CPEs) > 0 {
		return pkg.CPEString(p.CPEs[0])
	}
	return ""
}

func decodeCPEs(c *cyclonedx.Component) ([]pkg.CPE, error) {
	// FIXME -- why are we not encoding all the CPEs and what is the right behavior to decode them?
	cp, err := pkg.NewCPE(c.CPE)
	if err != nil {
		return nil, err
	}
	return cpe.Generate(pkg.Package{
		Name:         c.Name,
		Version:      c.Version,
		FoundBy:      "",
		Locations:    nil,
		Licenses:     nil,
		Language:     "",
		Type:         "",
		CPEs:         []pkg.CPE{cp},
		PURL:         c.PackageURL,
		MetadataType: "",
		Metadata:     nil,
	}), nil
}
