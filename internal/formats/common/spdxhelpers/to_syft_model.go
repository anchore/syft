package spdxhelpers

import (
	"strconv"
	"strings"

	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/packageurl-go"
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
			LinuxDistribution: findLinuxReleaseByPURL(doc),
		},
		Relationships: toSyftRelationships(spdxIDMap, doc),
	}, nil
}

func findLinuxReleaseByPURL(doc *spdx.Document2_2) *linux.Release {
	for _, p := range doc.Packages {
		purlValue := findPURLValue(p)
		if purlValue == "" {
			continue
		}
		purl, err := packageurl.FromString(purlValue)
		if err != nil {
			log.Warnf("unable to parse purl: %s", purlValue)
			continue
		}
		distro := findQualifierValue(purl, pkg.PURLQualifierDistro)
		if distro != "" {
			parts := strings.Split(distro, "-")
			name := parts[0]
			version := ""
			if len(parts) > 1 {
				version = parts[1]
			}
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
			log.Debugf("ignoring relationship to external document: %+v", r)
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
		if toLocationOk {
			switch RelationshipType(r.Relationship) {
			case ContainsRelationship:
				from.Locations = append(from.Locations, *toLocation)
				typ = artifact.ContainsRelationship
				to = toLocation
			}
		} else {
			switch RelationshipType(r.Relationship) {
			case ContainsRelationship:
				typ = artifact.ContainsRelationship
				to = toLocation
			case BuildDependencyOfRelationship:
				typ = artifact.BuildDependencyOfRelationship
				to = toPackage
			case RuntimeDependencyOfRelationship:
				typ = artifact.RuntimeDependencyOfRelationship
				to = toPackage
			case OtherRelationship:
				// Encoding uses a specifically formatted comment...
				if strings.Index(r.RelationshipComment, string(artifact.OwnershipByFileOverlapRelationship)) == 0 {
					typ = artifact.RuntimeDependencyOfRelationship
					to = toPackage
				}
			}
		}
		if typ != "" && to != nil {
			out = append(out, artifact.Relationship{
				From: from,
				To:   to,
				Type: typ,
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
	return findQualifierValue(p.purl, name)
}

func findQualifierValue(purl packageurl.PackageURL, qualifier string) string {
	for _, q := range purl.Qualifiers {
		if q.Key == qualifier {
			return q.Value
		}
	}
	return ""
}

func extractPkgInfo(p *spdx.Package2_2) pkgInfo {
	pu := findPURLValue(p)
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
	arch := info.qualifierValue(pkg.PURLQualifierArch)
	upstreamValue := info.qualifierValue(pkg.PURLQualifierUpstream)
	upstream := strings.SplitN(upstreamValue, "@", 2)
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
			Architecture:  arch,
			URL:           p.PackageHomePage,
			Description:   p.PackageDescription,
		}
	case pkg.RpmPkg:
		converted, err := strconv.Atoi(info.qualifierValue(pkg.PURLQualifierEpoch))
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
			Arch:      arch,
			SourceRpm: upstreamValue,
			License:   p.PackageLicenseConcluded,
			Vendor:    p.PackageOriginatorOrganization,
		}
	case pkg.DebPkg:
		return pkg.DpkgMetadataType, pkg.DpkgMetadata{
			Package:       p.PackageName,
			Source:        upstreamName,
			Version:       p.PackageVersion,
			SourceVersion: upstreamVersion,
			Architecture:  arch,
			Maintainer:    p.PackageOriginatorPerson,
		}
	}
	return pkg.UnknownMetadataType, nil
}

func findPURLValue(p *spdx.Package2_2) string {
	for _, r := range p.PackageExternalReferences {
		if r.RefType == string(PurlExternalRefType) {
			return r.Locator
		}
	}
	return ""
}

func extractCPEs(p *spdx.Package2_2) (cpes []pkg.CPE) {
	for _, r := range p.PackageExternalReferences {
		if r.RefType == string(Cpe23ExternalRefType) {
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
