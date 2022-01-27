package spdxhelpers

import (
	"strconv"
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
	spdxIDMap := make(map[string]interface{})

	collectSyftPackages(spdxIDMap, doc)

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
			LinuxDistribution: findSyftLinuxRelease(doc),
		},
		Relationships: toSyftRelationships(spdxIDMap, doc),
	}, nil
}

func findLinuxReleaseByDocument(doc *spdx.Document2_2) *linux.Release {
	var p *spdx.Package2_2

	if r := findSpdxRelationshipByType(doc, "DESCRIBES"); r != nil {
		if string(r.RefA.ElementRefID) == "DOCUMENT" {
			p = findSpdxPackageByID(doc, r.RefB.ElementRefID)
		}
	}

	if r := findSpdxRelationshipByType(doc, "DESCRIBED_BY"); r != nil {
		if string(r.RefB.ElementRefID) == "DOCUMENT" {
			p = findSpdxPackageByID(doc, r.RefA.ElementRefID)
		}
	}

	var name string
	var version string

	if p != nil {
		name = p.PackageName
		version = p.PackageVersion
	}

	if p != nil && (name == "" || version == "") {
		// SPDX has relationship: PACKAGE_OF
		// and Package External Reference PACKAGE-MANAGER
		// spec references "PACKAGE-MANAGER" but JSON schema has "PACKAGE_MANAGER"
		ref := findSpdxReferenceByName(p, "PACKAGE-MANAGER", "PACKAGE_MANAGER")

		if ref != nil {
			parts := strings.Split(ref.Locator, "-")
			if len(parts) > 1 {
				name = parts[0]
				version = parts[1]
			}
		}
	}

	if name != "" && version != "" {
		return &linux.Release{
			PrettyName: name,
			Name:       name,
			ID:         name,
			IDLike:     []string{name},
			Version:    version,
			VersionID:  version,
		}
	}

	return nil
}

func findLinuxReleaseByPURL(doc *spdx.Document2_2) *linux.Release {
	for _, p := range doc.Packages {
		purlValue := extractPURL(p)
		if purlValue != "" {
			purl, err := packageurl.FromString(purlValue)
			if err != nil {
				log.Warnf("unable to parse purl: %s", purlValue)
			} else {
				for _, qualifier := range purl.Qualifiers {
					if qualifier.Key == "distro" {
						parts := strings.Split(qualifier.Value, "-")
						if len(parts) > 1 {
							name := parts[0]
							version := parts[1]
							return &linux.Release{
								PrettyName: name,
								Name:       name,
								ID:         name,
								IDLike:     []string{name},
								Version:    version,
								VersionID:  version,
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func findSyftLinuxRelease(doc *spdx.Document2_2) *linux.Release {
	r := findLinuxReleaseByDocument(doc)
	if r != nil {
		return r
	}

	r = findLinuxReleaseByPURL(doc)
	if r != nil {
		return r
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

func collectSyftPackages(spdxIDMap map[string]interface{}, doc *spdx.Document2_2) {
	for _, p := range doc.Packages {
		syftPkg := toSyftPackage(p)
		spdxIDMap[string(p.PackageSPDXIdentifier)] = syftPkg
		for _, f := range p.Files {
			loc := toSyftLocation(f)
			syftPkg.Locations = append(syftPkg.Locations, *loc)
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

type pkgInfo struct {
	purl packageurl.PackageURL
	typ  pkg.Type
	lang pkg.Language
}

func (p *pkgInfo) qualifierValue(name string) string {
	for _, q := range p.purl.Qualifiers {
		if q.Key == name {
			return q.Value
		}
	}
	return ""
}

func extractPkgInfo(p *spdx.Package2_2) pkgInfo {
	pu := extractPURL(p)
	purl, err := packageurl.FromString(pu)
	if err != nil {
		return pkgInfo{}
	}
	return pkgInfo{
		purl,
		pkg.TypeByName(purl.Type),
		pkg.LanguageByName(purl.Type),
	}
}

func toSyftPackage(p *spdx.Package2_2) *pkg.Package {
	info := extractPkgInfo(p)
	metadataType, metadata := extractMetadata(p, info)
	sP := pkg.Package{
		Type:         info.typ,
		Name:         p.PackageName,
		Version:      p.PackageVersion,
		Licenses:     parseLicense(p.PackageLicenseDeclared),
		CPEs:         extractCPEs(p),
		PURL:         info.purl.String(),
		Language:     info.lang,
		MetadataType: metadataType,
		Metadata:     metadata,
	}

	sP.SetID()

	return &sP
}

func extractMetadata(p *spdx.Package2_2, info pkgInfo) (pkg.MetadataType, interface{}) {
	upstream := strings.Split(info.qualifierValue(pkg.UpstreamQualifier), "@")
	upstreamName := upstream[0]
	upstreamVersion := ""
	if len(upstream) > 1 {
		upstreamVersion = upstream[1]
	}
	switch info.typ {
	case pkg.ApkPkg:
		return pkg.ApkMetadataType, pkg.ApkMetadata{
			Package:       p.PackageName,
			OriginPackage: upstreamName,
			Maintainer:    p.PackageSupplierPerson,
			Version:       p.PackageVersion,
			License:       p.PackageLicenseDeclared,
			Architecture:  info.qualifierValue(pkg.ArchQualifier),
			URL:           p.PackageHomePage,
			Description:   p.PackageDescription,
		}
	case pkg.RpmPkg:
		converted, err := strconv.Atoi(info.qualifierValue(pkg.EpochQualifier))
		var epoch *int
		if err != nil {
			epoch = nil
		} else {
			epoch = &converted
		}
		return pkg.RpmdbMetadataType, pkg.RpmdbMetadata{
			Name:      p.PackageName,
			Version:   p.PackageVersion,
			Epoch:     epoch,
			Arch:      info.qualifierValue(pkg.ArchQualifier),
			SourceRpm: info.qualifierValue(pkg.UpstreamQualifier),
			License:   p.PackageLicenseConcluded,
			Vendor:    p.PackageOriginatorOrganization,
		}
	case pkg.DebPkg:
		return pkg.DpkgMetadataType, pkg.DpkgMetadata{
			Package:       p.PackageName,
			Source:        upstreamName,
			Version:       p.PackageVersion,
			SourceVersion: upstreamVersion,
			Architecture:  info.qualifierValue(pkg.ArchQualifier),
			Maintainer:    p.PackageOriginatorPerson,
		}
	}
	return pkg.UnknownMetadataType, nil
}

func extractPURL(p *spdx.Package2_2) string {
	for _, r := range p.PackageExternalReferences {
		if r.RefType == string(model.PurlExternalRefType) {
			return r.Locator
		}
	}
	return ""
}

func extractCPEs(p *spdx.Package2_2) (cpes []pkg.CPE) {
	for _, r := range p.PackageExternalReferences {
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
