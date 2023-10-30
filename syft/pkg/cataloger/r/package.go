package r

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func newPackage(pd parseData, locations ...file.Location) pkg.Package {
	locationSet := file.NewLocationSet()
	for _, loc := range locations {
		locationSet.Add(loc.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
	}

	licenses := parseLicenseData(pd.License)

	result := pkg.Package{
		Name:      pd.Package,
		Version:   pd.Version,
		Locations: locationSet,
		Licenses:  pkg.NewLicenseSet(licenses...),
		Language:  pkg.R,
		Type:      pkg.Rpkg,
		PURL:      packageURL(pd),
		Metadata:  pd.RDescription,
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
func parseLicenseData(license string, locations ...file.Location) []pkg.License {
	licenses := make([]pkg.License, 0)

	// check if multiple licenses are separated by |
	splitField := strings.Split(license, "|")
	for _, l := range splitField {
		// check case 1 for surrounding parens
		l = strings.TrimSpace(l)
		if strings.Contains(l, "(") && strings.Contains(l, ")") {
			licenseVersion := strings.SplitN(l, " ", 2)
			if len(licenseVersion) == 2 {
				l = strings.Join([]string{licenseVersion[0], parseVersion(licenseVersion[1])}, "")
				licenses = append(licenses, pkg.NewLicenseFromLocations(l, locations...))
				continue
			}
		}

		// case 3
		if strings.Contains(l, "+") && strings.Contains(l, "LICENSE") {
			splitField := strings.Split(l, " ")
			if len(splitField) > 0 {
				licenses = append(licenses, pkg.NewLicenseFromLocations(splitField[0], locations...))
				continue
			}
		}

		// TODO: case 4 if we are able to read the location data and find the adjacent file?
		if l == "file LICENSE" {
			continue
		}

		// no specific case found for the above so assume case 2
		// check if the common name in case 2 is valid SDPX otherwise value will be populated
		licenses = append(licenses, pkg.NewLicenseFromLocations(l, locations...))
		continue
	}
	return licenses
}

// attempt to make best guess at SPDX license ID from version operator in case 2
/*
‘<’, ‘<=’, ‘>’, ‘>=’, ‘==’, or ‘!=’
cant be (>= 2.0) OR (>= 2.0, < 3)
since there is no way in SPDX licenses to express < some other version
we attempt to check the constraint to see if this should be + or not
*/
func parseVersion(version string) string {
	version = strings.ReplaceAll(version, "(", "")
	version = strings.ReplaceAll(version, ")", "")

	// multiple constraints
	if strings.Contains(version, ",") {
		multipleConstraints := strings.Split(version, ",")
		// SPDX does not support considering multiple constraints
		// so we will just take the first one and attempt to form the best SPDX ID we can
		for _, v := range multipleConstraints {
			constraintVersion := strings.SplitN(v, " ", 2)
			if len(constraintVersion) == 2 {
				// switch on the operator and return the version with + or without
				switch constraintVersion[0] {
				case ">", ">=":
					return constraintVersion[1] + "+"
				default:
					return constraintVersion[1]
				}
			}
		}
	}
	// single constraint
	singleContraint := strings.Split(version, " ")
	if len(singleContraint) == 2 {
		switch singleContraint[0] {
		case ">", ">=":
			return singleContraint[1] + "+"
		default:
			return singleContraint[1]
		}
	}

	// could not parse version constraint so return ""
	return ""
}
