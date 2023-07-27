package spdxhelpers

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/common/util"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func ToSyftModel(doc *spdx.Document) (*sbom.SBOM, error) {
	if doc == nil {
		return nil, errors.New("cannot convert SPDX document to Syft model because document is nil")
	}

	spdxIDMap := make(map[string]any)

	s := &sbom.SBOM{
		Source: extractSource(spdxIDMap, doc),
		Artifacts: sbom.Artifacts{
			Packages:          pkg.NewCollection(),
			FileMetadata:      map[file.Coordinates]file.Metadata{},
			FileDigests:       map[file.Coordinates][]file.Digest{},
			LinuxDistribution: findLinuxReleaseByPURL(doc),
		},
	}

	collectSyftPackages(s, spdxIDMap, doc.Packages)

	collectSyftFiles(s, spdxIDMap, doc)

	s.Relationships = toSyftRelationships(spdxIDMap, doc)

	return s, nil
}

func isDirectory(name string) bool {
	if name == "." || name == ".." || strings.HasSuffix(name, "/") || !strings.Contains(path.Base(name), ".") {
		return true
	}
	return false
}

func removePackage(packages []*spdx.Package, remove *spdx.Package) (pkgs []*spdx.Package) {
	for _, p := range packages {
		if p == remove {
			continue
		}
		pkgs = append(pkgs, p)
	}
	return
}

func removeRelationships(relationships []*spdx.Relationship, spdxID spdx.ElementID) (relations []*spdx.Relationship) {
	for _, r := range relationships {
		if r.RefA.ElementRefID == spdxID || r.RefB.ElementRefID == spdxID {
			continue
		}
		relations = append(relations, r)
	}
	return
}

func findRootPackages(doc *spdx.Document) (out []*spdx.Package) {
	for _, p := range doc.Packages {
		for _, r := range doc.Relationships {
			describes := r.RefA.ElementRefID == "DOCUMENT" &&
				r.Relationship == spdx.RelationshipDescribes &&
				r.RefB.ElementRefID == p.PackageSPDXIdentifier

			describedBy := r.RefB.ElementRefID == "DOCUMENT" &&
				r.Relationship == spdx.RelationshipDescribedBy &&
				r.RefA.ElementRefID == p.PackageSPDXIdentifier

			if !describes && !describedBy {
				continue
			}

			out = append(out, p)
		}
	}
	return
}

func extractSource(spdxIDMap map[string]any, doc *spdx.Document) source.Description {
	src := extractSourceFromNamespace(doc.DocumentNamespace)

	rootPackages := findRootPackages(doc)

	if len(rootPackages) != 1 {
		return src
	}

	p := rootPackages[0]

	switch p.PrimaryPackagePurpose {
	case spdxPrimaryPurposeContainer:
		src = containerSource(p)
	case spdxPrimaryPurposeFile:
		src = fileSource(p)
	default:
		return src
	}

	spdxIDMap[string(p.PackageSPDXIdentifier)] = src

	doc.Packages = removePackage(doc.Packages, p)
	doc.Relationships = removeRelationships(doc.Relationships, p.PackageSPDXIdentifier)

	return src
}

func containerSource(p *spdx.Package) source.Description {
	id := string(p.PackageSPDXIdentifier)

	container := p.PackageName
	v := p.PackageVersion
	if v != "" {
		container += ":" + v
	}

	digest := ""
	if len(p.PackageChecksums) > 0 {
		c := p.PackageChecksums[0]
		digest = fmt.Sprintf("%s:%s", fromChecksumAlgorithm(c.Algorithm), c.Value)
	}
	return source.Description{
		ID:      id,
		Name:    p.PackageName,
		Version: p.PackageVersion,
		Metadata: source.StereoscopeImageSourceMetadata{
			UserInput:      container,
			ID:             id,
			Layers:         nil, // TODO handle formats with nested layer packages like Tern and K8s BOM tool
			ManifestDigest: digest,
		},
	}
}

func fileSource(p *spdx.Package) source.Description {
	typeRegex := regexp.MustCompile("^DocumentRoot-([^-]+)-.*$")
	typeName := typeRegex.ReplaceAllString(string(p.PackageSPDXIdentifier), "$1")

	var version string
	var metadata any
	switch {
	case typeName == prefixDirectory:
		// is a Syft SBOM, explicitly a directory source
		metadata, version = directorySourceMetadata(p)
	case typeName == prefixFile:
		// is a Syft SBOM, explicitly a file source
		metadata, version = fileSourceMetadata(p)
	case isDirectory(p.PackageName):
		// is a non-Syft SBOM, which looks like a directory
		metadata, version = directorySourceMetadata(p)
	default:
		// is a non-Syft SBOM, which is probably a file
		metadata, version = fileSourceMetadata(p)
	}

	return source.Description{
		ID:       string(p.PackageSPDXIdentifier),
		Name:     p.PackageName,
		Version:  version,
		Metadata: metadata,
	}
}

func fileSourceMetadata(p *spdx.Package) (any, string) {
	version := p.PackageVersion

	m := source.FileSourceMetadata{
		Path: p.PackageName,
	}
	// if this is a Syft SBOM, we might have output a digest as the version
	checksum := toChecksum(p.PackageVersion)
	for _, d := range p.PackageChecksums {
		if checksum != nil && checksum.Value == d.Value {
			version = ""
		}
		m.Digests = append(m.Digests, file.Digest{
			Algorithm: fromChecksumAlgorithm(d.Algorithm),
			Value:     d.Value,
		})
	}

	return m, version
}

func directorySourceMetadata(p *spdx.Package) (any, string) {
	return source.DirectorySourceMetadata{
		Path: p.PackageName,
		Base: "",
	}, p.PackageVersion
}

// NOTE(jonas): SPDX doesn't inform what an SBOM is about,
// image, directory, for example. This is our best effort to determine
// the scheme. Syft-generated SBOMs have in the namespace
// field a type encoded, which we try to identify here.
func extractSourceFromNamespace(ns string) source.Description {
	u, err := url.Parse(ns)
	if err != nil {
		return source.Description{
			Metadata: nil,
		}
	}

	parts := strings.Split(u.Path, "/")
	for _, p := range parts {
		switch p {
		case inputFile:
			return source.Description{
				Metadata: source.FileSourceMetadata{},
			}
		case inputImage:
			return source.Description{
				Metadata: source.StereoscopeImageSourceMetadata{},
			}
		case inputDirectory:
			return source.Description{
				Metadata: source.DirectorySourceMetadata{},
			}
		}
	}
	return source.Description{}
}

func findLinuxReleaseByPURL(doc *spdx.Document) *linux.Release {
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

func collectSyftPackages(s *sbom.SBOM, spdxIDMap map[string]any, packages []*spdx.Package) {
	for _, p := range packages {
		syftPkg := toSyftPackage(p)
		spdxIDMap[string(p.PackageSPDXIdentifier)] = syftPkg
		s.Artifacts.Packages.Add(syftPkg)
	}
}

func collectSyftFiles(s *sbom.SBOM, spdxIDMap map[string]any, doc *spdx.Document) {
	for _, f := range doc.Files {
		l := toSyftLocation(f)
		spdxIDMap[string(f.FileSPDXIdentifier)] = l

		s.Artifacts.FileMetadata[l.Coordinates] = toFileMetadata(f)
		s.Artifacts.FileDigests[l.Coordinates] = toFileDigests(f)
	}
}

func toFileDigests(f *spdx.File) (digests []file.Digest) {
	for _, digest := range f.Checksums {
		digests = append(digests, file.Digest{
			Algorithm: fromChecksumAlgorithm(digest.Algorithm),
			Value:     digest.Value,
		})
	}
	return digests
}

func fromChecksumAlgorithm(algorithm common.ChecksumAlgorithm) string {
	return strings.ToLower(string(algorithm))
}

func toFileMetadata(f *spdx.File) (meta file.Metadata) {
	// FIXME Syft is currently lossy due to the SPDX 2.2.1 spec not supporting arbitrary mimetypes
	for _, typ := range f.FileTypes {
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

func toSyftRelationships(spdxIDMap map[string]any, doc *spdx.Document) []artifact.Relationship {
	var out []artifact.Relationship
	for _, r := range doc.Relationships {
		// FIXME what to do with r.RefA.DocumentRefID and r.RefA.SpecialID
		if r.RefA.DocumentRefID != "" && requireAndTrimPrefix(r.RefA.DocumentRefID, "DocumentRef-") != string(doc.SPDXIdentifier) {
			log.Debugf("ignoring relationship to external document: %+v", r)
			continue
		}
		a := spdxIDMap[string(r.RefA.ElementRefID)]
		b := spdxIDMap[string(r.RefB.ElementRefID)]
		from, fromOk := a.(pkg.Package)
		toPackage, toPackageOk := b.(pkg.Package)
		toLocation, toLocationOk := b.(file.Location)
		if !fromOk || !(toPackageOk || toLocationOk) {
			log.Debugf("unable to find valid relationship mapping from SPDX, ignoring: (from: %+v) (to: %+v)", a, b)
			continue
		}
		var to artifact.Identifiable
		var typ artifact.RelationshipType
		if toLocationOk {
			switch RelationshipType(r.Relationship) {
			case ContainsRelationship:
				typ = artifact.ContainsRelationship
				to = toLocation
			case OtherRelationship:
				// Encoding uses a specifically formatted comment...
				if strings.Index(r.RelationshipComment, string(artifact.EvidentByRelationship)) == 0 {
					typ = artifact.EvidentByRelationship
					to = toLocation
				}
			}
		} else {
			switch RelationshipType(r.Relationship) {
			case ContainsRelationship:
				typ = artifact.ContainsRelationship
				to = toPackage
			case OtherRelationship:
				// Encoding uses a specifically formatted comment...
				if strings.Index(r.RelationshipComment, string(artifact.OwnershipByFileOverlapRelationship)) == 0 {
					typ = artifact.OwnershipByFileOverlapRelationship
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

func toSyftCoordinates(f *spdx.File) file.Coordinates {
	const layerIDPrefix = "layerID: "
	var fileSystemID string
	if strings.Index(f.FileComment, layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(f.FileComment, layerIDPrefix)
	}
	if strings.Index(string(f.FileSPDXIdentifier), layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(string(f.FileSPDXIdentifier), layerIDPrefix)
	}
	return file.Coordinates{
		RealPath:     f.FileName,
		FileSystemID: fileSystemID,
	}
}

func toSyftLocation(f *spdx.File) file.Location {
	l := file.NewVirtualLocationFromCoordinates(toSyftCoordinates(f), f.FileName)
	return l
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

func extractPkgInfo(p *spdx.Package) pkgInfo {
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

func toSyftPackage(p *spdx.Package) pkg.Package {
	info := extractPkgInfo(p)
	metadataType, metadata := extractMetadata(p, info)
	sP := &pkg.Package{
		Type:         info.typ,
		Name:         p.PackageName,
		Version:      p.PackageVersion,
		Licenses:     pkg.NewLicenseSet(parseSPDXLicenses(p)...),
		CPEs:         extractCPEs(p),
		PURL:         purlValue(info.purl),
		Language:     info.lang,
		MetadataType: metadataType,
		Metadata:     metadata,
	}

	sP.SetID()

	return *sP
}

func purlValue(purl packageurl.PackageURL) string {
	p := purl.String()
	if p == "pkg:/" {
		return ""
	}
	return p
}

func parseSPDXLicenses(p *spdx.Package) []pkg.License {
	licenses := make([]pkg.License, 0)

	// concluded
	if p.PackageLicenseConcluded != NOASSERTION && p.PackageLicenseConcluded != NONE && p.PackageLicenseConcluded != "" {
		l := pkg.NewLicense(cleanSPDXID(p.PackageLicenseConcluded))
		l.Type = license.Concluded
		licenses = append(licenses, l)
	}

	// declared
	if p.PackageLicenseDeclared != NOASSERTION && p.PackageLicenseDeclared != NONE && p.PackageLicenseDeclared != "" {
		l := pkg.NewLicense(cleanSPDXID(p.PackageLicenseDeclared))
		l.Type = license.Declared
		licenses = append(licenses, l)
	}

	return licenses
}

func cleanSPDXID(id string) string {
	if strings.HasPrefix(id, "LicenseRef-") {
		return strings.TrimPrefix(id, "LicenseRef-")
	}
	return id
}

//nolint:funlen
func extractMetadata(p *spdx.Package, info pkgInfo) (pkg.MetadataType, interface{}) {
	arch := info.qualifierValue(pkg.PURLQualifierArch)
	upstreamValue := info.qualifierValue(pkg.PURLQualifierUpstream)
	upstream := strings.SplitN(upstreamValue, "@", 2)
	upstreamName := upstream[0]
	upstreamVersion := ""
	if len(upstream) > 1 {
		upstreamVersion = upstream[1]
	}
	supplier := ""
	if p.PackageSupplier != nil {
		supplier = p.PackageSupplier.Supplier
	}
	originator := ""
	if p.PackageOriginator != nil {
		originator = p.PackageOriginator.Originator
	}
	switch info.typ {
	case pkg.ApkPkg:
		return pkg.ApkMetadataType, pkg.ApkMetadata{
			Package:       p.PackageName,
			OriginPackage: upstreamName,
			Maintainer:    supplier,
			Version:       p.PackageVersion,
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
		return pkg.RpmMetadataType, pkg.RpmMetadata{
			Name:      p.PackageName,
			Version:   p.PackageVersion,
			Epoch:     epoch,
			Arch:      arch,
			SourceRpm: upstreamValue,
			Vendor:    originator,
		}
	case pkg.DebPkg:
		return pkg.DpkgMetadataType, pkg.DpkgMetadata{
			Package:       p.PackageName,
			Source:        upstreamName,
			Version:       p.PackageVersion,
			SourceVersion: upstreamVersion,
			Architecture:  arch,
			Maintainer:    originator,
		}
	case pkg.JavaPkg:
		var digests []file.Digest
		for _, value := range p.PackageChecksums {
			digests = append(digests, file.Digest{Algorithm: fromChecksumAlgorithm(value.Algorithm), Value: value.Value})
		}
		return pkg.JavaMetadataType, pkg.JavaMetadata{
			ArchiveDigests: digests,
		}
	case pkg.GoModulePkg:
		var h1Digest string
		for _, value := range p.PackageChecksums {
			digest, err := util.HDigestFromSHA(fromChecksumAlgorithm(value.Algorithm), value.Value)
			if err != nil {
				log.Debugf("invalid h1digest: %v %v", value, err)
				continue
			}
			h1Digest = digest
			break
		}
		return pkg.GolangBinMetadataType, pkg.GolangBinMetadata{
			H1Digest: h1Digest,
		}
	}
	return pkg.UnknownMetadataType, nil
}

func findPURLValue(p *spdx.Package) string {
	for _, r := range p.PackageExternalReferences {
		if r.RefType == string(PurlExternalRefType) {
			return r.Locator
		}
	}
	return ""
}

func extractCPEs(p *spdx.Package) (cpes []cpe.CPE) {
	for _, r := range p.PackageExternalReferences {
		if r.RefType == string(Cpe23ExternalRefType) {
			c, err := cpe.New(r.Locator)
			if err != nil {
				log.Warnf("unable to extract SPDX CPE=%q: %+v", r.Locator, err)
				continue
			}
			cpes = append(cpes, c)
		}
	}
	return cpes
}
