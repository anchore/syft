package spdxhelpers

import (
	"strings"

	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func ToSyftModel(doc *spdx.Document2_2) (*sbom.SBOM, error) {
	typ := pkg.UnknownPkg

	release := findSyftLinuxRelease(doc)
	if release != nil {
		typ = pkg.PackageTypeByName(release.Name)
	}

	spdxIDMap := make(map[string]interface{})

	collectSyftPackages(spdxIDMap, doc, typ)

	collectSyftFiles(spdxIDMap, doc)

	catalog := pkg.NewCatalog()

	for _, v := range spdxIDMap {
		if p, ok := v.(*pkg.Package); ok {
			catalog.Add(*p)
		}
	}

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog:    catalog,
			LinuxDistribution: release,
		},
		Relationships: toSyftRelationships(spdxIDMap, doc),
	}, nil
}

func findSyftLinuxRelease(doc *spdx.Document2_2) *linux.Release {
	var releaseName string
	var releaseVersion string

	var release *spdx.Package2_2

	if r := findSpdxRelationshipByType(doc, "DESCRIBES"); r != nil {
		if string(r.RefA.ElementRefID) == "DOCUMENT" {
			release = findSpdxPackageByID(doc, r.RefB.ElementRefID)
		}
	}

	if r := findSpdxRelationshipByType(doc, "DESCRIBED_BY"); r != nil {
		if string(r.RefB.ElementRefID) == "DOCUMENT" {
			release = findSpdxPackageByID(doc, r.RefA.ElementRefID)
		}
	}

	if release != nil {
		releaseName = release.PackageName
		releaseVersion = release.PackageVersion
	} else {
		categories := []string{"PACKAGE-MANAGER", "PACKAGE_MANAGER"}

		var ref *spdx.PackageExternalReference2_2

		if release != nil {
			// SPDX has relationship: PACKAGE_OF
			// and Package External Reference PACKAGE-MANAGER
			// spec references "PACKAGE-MANAGER" but JSON schema has "PACKAGE_MANAGER"
			ref = findSpdxReferenceByName(release, categories...)
		}

		if ref == nil {
		nextPackage:
			for _, p := range doc.Packages {
				purlValue := extractPURL(p.PackageExternalReferences)
				if purlValue != "" {
					purl, err := packageurl.FromString(purlValue)
					if err != nil {
						log.Warnf("unable to parse purl: %s", purlValue)
					} else {
						for _, qualifier := range purl.Qualifiers {
							if qualifier.Key == "distro" {
								parts := strings.Split(qualifier.Value, "-")
								if len(parts) > 1 {
									releaseName = parts[0]
									releaseVersion = parts[1]
									break nextPackage
								}
							}
						}
					}
				}
			}
		}
	}

	if releaseName != "" && releaseVersion != "" {
		return &linux.Release{
			PrettyName: releaseName,
			Name:       releaseName,
			ID:         releaseName,
			IDLike:     []string{releaseName},
			Version:    releaseVersion,
			VersionID:  releaseVersion,
		}
	}

	return nil
}

func findSpdxRelationshipByType(doc *spdx.Document2_2, typ string) *spdx.Relationship2_2 {
	for _, r := range doc.Relationships {
		if typ == r.Relationship {
			return r
		}
	}
	return nil
}

func findSpdxPackageByID(doc *spdx.Document2_2, id spdx.ElementID) *spdx.Package2_2 {
	for _, p := range doc.Packages {
		if p.PackageSPDXIdentifier == id {
			return p
		}
	}
	return nil
}

func findSpdxReferenceByName(p *spdx.Package2_2, categories ...string) *spdx.PackageExternalReference2_2 {
	for _, r := range p.PackageExternalReferences {
		for _, category := range categories {
			if r.Category == category {
				return r
			}
		}
	}
	return nil
}

func collectSyftFiles(spdxIDMap map[string]interface{}, doc *spdx.Document2_2) {
	for _, f := range doc.UnpackagedFiles {
		spdxIDMap[string(f.FileSPDXIdentifier)] = toSyftLocation(f)
	}
}

func toSyftRelationships(spdxIDMap map[string]interface{}, doc *spdx.Document2_2) []artifact.Relationship {
	var out []artifact.Relationship
	for _, r := range doc.Relationships {
		// FIXME what to do with r.RefA.DocumentRefID and  r.RefA.SpecialID
		if r.RefA.DocumentRefID != "" && requireAndTrimPrefix(r.RefA.DocumentRefID, "DocumentRef-") != string(doc.CreationInfo.SPDXIdentifier) {
			log.Debugf("relationship to external document: %+v", r)
			continue
		}
		a := spdxIDMap[string(r.RefA.ElementRefID)]
		b := spdxIDMap[string(r.RefB.ElementRefID)]
		from, fromOk := a.(*pkg.Package)
		toPackage, toPackageOk := b.(*pkg.Package)
		toLocation, toLocationOk := b.(*source.Location)
		if !fromOk || !(toPackageOk || toLocationOk) {
			log.Debugf("unable to find valid relationship mapping from SPDX 2.2 JSON, ignoring: (from: %+v) (to: %+v)", a, b)
			continue
		}
		var to artifact.Identifiable
		var typ artifact.RelationshipType
		switch r.Relationship {
		case "CONTAINS":
			if toLocationOk {
				from.Locations = append(from.Locations, *toLocation)
				typ = artifact.ContainsRelationship
				to = toLocation
			}
		case "OVERWRITE":
			typ = artifact.OwnershipByFileOverlapRelationship
			to = toPackage
		}
		if typ != "" && to != nil {
			out = append(out, artifact.Relationship{
				From: from,
				To:   to,
				Type: typ,
				Data: nil, // FIXME should there be anything for this Data?
			})
		}
	}
	return out
}

func collectSyftPackages(spdxIDMap map[string]interface{}, doc *spdx.Document2_2, defaultType pkg.Type) {
	for _, p := range doc.Packages {
		syftPkg := toSyftPackage(p, defaultType)
		spdxIDMap[string(p.PackageSPDXIdentifier)] = &syftPkg
		for _, f := range p.Files {
			loc := toSyftLocation(f)
			syftPkg.Locations = append(syftPkg.Locations, *loc)
			// spdxIDMap[string(f.FileSPDXIdentifier)] = loc
		}
	}
}

func toSyftLocation(f *spdx.File2_2) *source.Location {
	return &source.Location{
		Coordinates: source.Coordinates{
			RealPath:     f.FileName,
			FileSystemID: requireAndTrimPrefix(f.FileSPDXIdentifier, "layerID: "),
		},
		VirtualPath: f.FileName,
	}
}

func requireAndTrimPrefix(val interface{}, prefix string) string {
	if v, ok := val.(string); ok {
		if i := strings.Index(v, prefix); i == 0 {
			return strings.Replace(v, prefix, "", 1)
		}
	}
	return ""
}

func toSyftPackage(p *spdx.Package2_2, defaultType pkg.Type) pkg.Package {
	purl := extractPURL(p.PackageExternalReferences)
	typ := pkg.PackageTypeFromPURL(purl)
	if typ == pkg.UnknownPkg {
		typ = defaultType
	}
	sP := pkg.Package{
		Type:     typ,
		Name:     p.PackageName,
		Version:  p.PackageVersion,
		Licenses: parseLicense(p.PackageLicenseDeclared),
		CPEs:     extractCPEs(p.PackageExternalReferences),
		PURL:     purl,
		Language: pkg.LanguageFromPURL(purl),
	}

	sP.SetID()

	return sP
}

func extractPURL(refs []*spdx.PackageExternalReference2_2) string {
	for _, r := range refs {
		if r.RefType == string(model.PurlExternalRefType) {
			return r.Locator
		}
	}
	return ""
}

func extractCPEs(refs []*spdx.PackageExternalReference2_2) (cpes []pkg.CPE) {
	for _, r := range refs {
		if r.RefType == string(model.Cpe23ExternalRefType) {
			cpe, err := pkg.NewCPE(r.Locator)
			if err != nil {
				log.Warnf("unable to extract SPDX CPE=%q: %+v", r.Locator, err)
				continue
			}
			cpes = append(cpes, cpe)
		}
	}
	return cpes
}

func parseLicense(l string) []string {
	if l == NOASSERTION || l == NONE {
		return nil
	}
	return strings.Split(l, " AND ")
}
