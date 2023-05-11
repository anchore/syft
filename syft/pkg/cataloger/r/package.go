package r

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func newPackage(pd parseData, locations ...source.Location) pkg.Package {
	locationSet := source.NewLocationSet()
	for _, loc := range locations {
		locationSet.Add(loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	}

	licenses := parseLicenseData(pd.License)

	result := pkg.Package{
		Name:         pd.Package,
		Version:      pd.Version,
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(licenses...),
		Language:     pkg.R,
		Type:         pkg.Rpkg,
		PURL:         packageURL(pd),
		MetadataType: pkg.RDescriptionFileMetadataType,
		Metadata:     pd.RDescriptionFileMetadata,
	}

	result.SetID()
	return result
}

func packageURL(m parseData) string {
	return packageurl.NewPackageURL("cran", "", m.Package, m.Version, nil, "").ToString()
}

// https://r-pkgs.org/description.html#the-license-field
// four forms:
// 1. "GPL (>= 2)"
// 2. "GPL-2"
// 3. "MIT + file LICENSE"
// 4. "pointer to the full text of the license; file LICENSE"
// Multiple licences can be specified separated by ‘|’
// (surrounded by spaces) in which case the user can choose any of the above cases.
// https://cran.rstudio.com/doc/manuals/r-devel/R-exts.html#Licensing
func parseLicenseData(license string, locations ...source.Location) []pkg.License {
	licenses := make([]pkg.License, 0)
	// check case 1 for surrounding parens
	if strings.Contains(license, "(") && strings.Contains(license, ")") {
		licenseVersion := strings.Split(license, " ")
		if len(licenseVersion) == 2 {
			license = strings.Join([]string{licenseVersion[0], parseVersion(licenseVersion[1])}, "")
			licenses = append(licenses, pkg.NewLicenseFromLocations(license, locations...))
			return licenses
		}
	}

	// case 3
	if strings.Contains(license, "+") && strings.Contains(license, "LICENSE") {
		splitField := strings.Split(license, " ")
		if len(splitField) > 0 {
			licenses = append(licenses, pkg.NewLicenseFromLocations(splitField[0], locations...))
			return licenses
		}
	}

	// TODO: case 4 if we are able to read the location data and find the adjacent file?

	// no specific case found for the above so assume case 2
	// check if the common name in case 2 is valid SDPX
	licenses = append(licenses, pkg.NewLicenseFromLocations(license, locations...))
	return licenses
}

// attempt to make best guess at SPDX license ID from version operator in case 2
/*
‘<’, ‘<=’, ‘>’, ‘>=’, ‘==’, or ‘!=’
*/
func parseVersion(version string) string {
	version = strings.ReplaceAll(version, "(", "")
	version = strings.ReplaceAll(version, ")", "")
	operatorVersion := strings.Split(version, " ")
	if len(operatorVersion) == 2 {
		version = operatorVersion[1]
		operator := operatorVersion[0]
		switch operator {
		case ">=":
			return version + "+"
		case "==":
			return version
		}
	}
	return version
}
