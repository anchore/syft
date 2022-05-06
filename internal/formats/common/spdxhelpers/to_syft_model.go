package spdxhelpers

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func ToSyftModel(doc *spdx.Document2_2) (*sbom.SBOM, error) {
	if doc == nil {
		return nil, errors.New("cannot convert SPDX document to Syft model because document is nil")
	}

	spdxIDMap := make(map[string]interface{})

	src := source.Metadata{Scheme: source.UnknownScheme}
	if doc.CreationInfo != nil {
		src.Scheme = extractSchemeFromNamespace(doc.CreationInfo.DocumentNamespace)
	}

	s := &sbom.SBOM{
		Source: src,
		Artifacts: sbom.Artifacts{
			PackageCatalog:    pkg.NewCatalog(),
			FileMetadata:      map[source.Coordinates]source.FileMetadata{},
			FileDigests:       map[source.Coordinates][]file.Digest{},
			LinuxDistribution: findLinuxReleaseByPURL(doc),
		},
	}

	collectSyftPackages(s, spdxIDMap, doc)

	collectSyftFiles(s, spdxIDMap, doc)

	s.Relationships = toSyftRelationships(spdxIDMap, doc)

	return s, nil
}

// NOTE(jonas): SPDX doesn't inform what an SBOM is about,
// image, directory, for example. This is our best effort to determine
// the scheme. Syft-generated SBOMs have in the namespace
// field a type encoded, which we try to identify here.
func extractSchemeFromNamespace(ns string) source.Scheme {
	u, err := url.Parse(ns)
	if err != nil {
		return source.UnknownScheme
	}

	parts := strings.Split(u.Path, "/")
	for _, p := range parts {
		switch p {
		case "file":
			return source.FileScheme
		case "image":
			return source.ImageScheme
		case "dir":
			return source.DirectoryScheme
		}
	}
	return source.UnknownScheme
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

func collectSyftPackages(s *sbom.SBOM, spdxIDMap map[string]interface{}, doc *spdx.Document2_2) {
	for _, p := range doc.Packages {
		syftPkg := toSyftPackage(p)
		spdxIDMap[string(p.PackageSPDXIdentifier)] = syftPkg
		s.Artifacts.PackageCatalog.Add(*syftPkg)
	}
}

func collectSyftFiles(s *sbom.SBOM, spdxIDMap map[string]interface{}, doc *spdx.Document2_2) {
	for _, f := range doc.UnpackagedFiles {
		l := toSyftLocation(f)
		spdxIDMap[string(f.FileSPDXIdentifier)] = l

		s.Artifacts.FileMetadata[l.Coordinates] = toFileMetadata(f)
		s.Artifacts.FileDigests[l.Coordinates] = toFileDigests(f)
	}
}

func toFileDigests(f *spdx.File2_2) (digests []file.Digest) {
	for _, digest := range f.FileChecksums {
		digests = append(digests, file.Digest{
			Algorithm: string(digest.Algorithm),
			Value:     digest.Value,
		})
	}
	return digests
}

func toFileMetadata(f *spdx.File2_2) (meta source.FileMetadata) {
	// FIXME Syft is currently lossy due to the SPDX 2.2.1 spec not supporting arbitrary mimetypes
	for _, typ := range f.FileType {
		switch FileType(typ) {
		case ImageFileType:
			meta.MIMEType = "image/"
		case VideoFileType:
			meta.MIMEType = "video/"
		case ApplicationFileType:
			meta.MIMEType = "application/"
		case TextFileType:
			meta.MIMEType = "text/"
		case AudioFileType:
			meta.MIMEType = "audio/"
		case BinaryFileType:
		case ArchiveFileType:
		case OtherFileType:
		}
	}
	return meta
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
			if r.Relationship == string(ContainsRelationship) {
				typ = artifact.ContainsRelationship
				to = toLocation
			}
		} else {
			switch RelationshipType(r.Relationship) {
			case ContainsRelationship:
				typ = artifact.ContainsRelationship
				to = toPackage
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

func toSyftCoordinates(f *spdx.File2_2) source.Coordinates {
	const layerIDPrefix = "layerID: "
	var fileSystemID string
	if strings.Index(f.FileComment, layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(f.FileComment, layerIDPrefix)
	}
	if strings.Index(string(f.FileSPDXIdentifier), layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(string(f.FileSPDXIdentifier), layerIDPrefix)
	}
	return source.Coordinates{
		RealPath:     f.FileName,
		FileSystemID: fileSystemID,
	}
}

func toSyftLocation(f *spdx.File2_2) *source.Location {
	return &source.Location{
		Coordinates: toSyftCoordinates(f),
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
	case pkg.JavaPkg:
		var digests []file.Digest
		for algorithm, value := range p.PackageChecksums {
			digests = append(digests, file.Digest{Algorithm: string(algorithm), Value: value.Value})
		}
		return pkg.JavaMetadataType, pkg.JavaMetadata{
			ArchiveDigests: digests,
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
