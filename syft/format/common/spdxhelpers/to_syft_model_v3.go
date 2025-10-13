package spdxhelpers

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/scylladb/go-set/strset"
	spdx "github.com/spdx/tools-golang/spdx/v3/v3_0_1"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/format/internal/spdx3/helpers"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func ToSyftModelV3(doc *spdx.Document) (*sbom.SBOM, error) {
	if doc == nil {
		return nil, errors.New("cannot convert SPDX document to Syft model because document is nil")
	}

	spdxIDMap := make(map[string]any)

	s := &sbom.SBOM{
		Source: v3extractSource(spdxIDMap, doc),
		Artifacts: sbom.Artifacts{
			Packages:          pkg.NewCollection(),
			FileMetadata:      map[file.Coordinates]file.Metadata{},
			FileDigests:       map[file.Coordinates][]file.Digest{},
			LinuxDistribution: v3findLinuxReleaseByPURL(doc),
		},
	}

	v3collectSyftPackages(s, spdxIDMap, doc)

	v3collectSyftFiles(s, spdxIDMap, doc)

	s.Relationships = v3toSyftRelationships(spdxIDMap, doc)

	return s, nil
}

func v3removePackage(packages spdx.ElementList, remove spdx.AnyPackage) (pkgs spdx.ElementList) {
	for _, p := range packages {
		if p == remove {
			continue
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func v3removeRelationships(elements spdx.ElementList, element spdx.AnyElement) (relations spdx.ElementList) {
	for _, e := range elements {
		if r, ok := e.(spdx.AnyRelationship); ok {
			if r != nil && r.GetFrom() == element {
				continue
			}

			if r != nil {
				var tos spdx.ElementList
				for _, to := range r.GetTo() {
					if to == element {
						continue
					}
					tos = append(tos, to)
				}
				r.SetTo(tos)
				if len(r.GetTo()) == 0 {
					continue
				}
			}

			relations = append(relations, r)
		} else {
			relations = append(relations, e)
		}
	}
	return relations
}

func v3findRootPackages(doc spdx.AnyElementCollection) (out spdx.PackageList) {
	for _, s := range doc.GetElements().ElementCollections() {
		root := v3findRootPackages(s)
		if root != nil {
			return root
		}
	}
	for _, s := range doc.GetRootElements().ElementCollections() {
		root := v3findRootPackages(s)
		if root != nil {
			return root
		}
	}
	for _, p := range doc.GetRootElements().Packages() {
		if p.GetPrimaryPurpose() != spdx.SoftwarePurpose_Container {
			continue
		}
		out = append(out, p)
	}
	for _, p := range doc.GetElements().Packages() {
		if p.GetPrimaryPurpose() != spdx.SoftwarePurpose_Container {
			continue
		}
		out = append(out, p)
	}
	return
}

func v3extractSource(spdxIDMap map[string]any, doc *spdx.Document) source.Description {
	namespace := doc.Name
	if len(doc.NamespaceMaps) > 0 {
		namespace = string(doc.NamespaceMaps[0].GetNamespace())
	}
	src := extractSourceFromNamespace(namespace)

	rootPackages := v3findRootPackages(doc)

	if len(rootPackages) != 1 {
		return src
	}

	p := rootPackages[0]

	switch p.GetPrimaryPurpose() {
	case spdx.SoftwarePurpose_Container:
		src = v3containerSource(p)
	case spdx.SoftwarePurpose_File:
		src = v3fileSource(p)
	default:
		return src
	}

	spdxIDMap[p.GetID()] = src

	doc.Elements = v3removePackage(doc.Elements, p)
	doc.Elements = v3removeRelationships(doc.Elements, p)

	return src
}

func v3containerSource(p spdx.AnyPackage) source.Description {
	container := p.GetName()
	v := p.GetVersion()
	if v != "" {
		container += ":" + v
	}

	digest := ""
	if len(p.GetVerifiedUsing().IntegrityMethods()) > 0 {
		c := p.GetVerifiedUsing().IntegrityMethods()[0]
		h, _ := c.(spdx.AnyHash)
		if h != nil {
			digest = fmt.Sprintf("%s:%s", v3fromChecksumAlgorithm(h.GetAlgorithm()), h.GetValue())
		}
	}
	return source.Description{
		ID:      p.GetID(),
		Name:    p.GetName(),
		Version: p.GetVersion(),
		Metadata: source.ImageMetadata{
			UserInput:      container,
			ID:             p.GetID(),
			Layers:         nil, // TODO handle formats with nested layer packages like Tern and K8s BOM tool
			ManifestDigest: digest,
		},
	}
}

func v3fileSource(p spdx.AnyPackage) source.Description {
	typeRegex := regexp.MustCompile("^DocumentRoot-([^-]+)-.*$")
	typeName := typeRegex.ReplaceAllString(p.GetID(), "$1")

	var version string
	var metadata any
	switch {
	case typeName == prefixDirectory:
		// is a Syft SBOM, explicitly a directory source
		metadata, version = v3directorySourceMetadata(p)
	case typeName == prefixFile:
		// is a Syft SBOM, explicitly a file source
		metadata, version = v3fileSourceMetadata(p)
	case isDirectory(p.GetName()):
		// is a non-Syft SBOM, which looks like a directory
		metadata, version = v3directorySourceMetadata(p)
	default:
		// is a non-Syft SBOM, which is probably a file
		metadata, version = v3fileSourceMetadata(p)
	}

	return source.Description{
		ID:       p.GetID(),
		Name:     p.GetName(),
		Version:  version,
		Metadata: metadata,
	}
}

func v3fileSourceMetadata(p spdx.AnyPackage) (any, string) {
	version := p.GetVersion()

	m := source.FileMetadata{
		Path: p.GetName(),
	}
	// if this is a Syft SBOM, we might have output a digest as the version
	checksum := v3toChecksum(p.GetVersion())
	for _, i := range p.GetVerifiedUsing() {
		d, _ := i.(spdx.AnyHash)
		if d == nil {
			continue
		}
		if checksum != nil && checksum.GetValue() == d.GetValue() {
			version = ""
		}
		m.Digests = append(m.Digests, file.Digest{
			Algorithm: v3fromChecksumAlgorithm(d.GetAlgorithm()),
			Value:     d.GetValue(),
		})
	}

	return m, version
}

// toChecksum takes a checksum in the format <algorithm>:<hash> and returns an spdx.Checksum or nil if the string is invalid
func v3toChecksum(algorithmHash string) spdx.AnyHash {
	parts := strings.Split(algorithmHash, ":")
	if len(parts) < 2 {
		return nil
	}
	return &spdx.Hash{
		Algorithm: v3toChecksumAlgorithm(parts[0]),
		Value:     parts[1],
	}
}

func v3toChecksumAlgorithm(algorithm string) spdx.HashAlgorithm {
	// this needs to be an uppercase version of our algorithm
	switch strings.ToLower(algorithm) {
	case "sha1":
		return spdx.HashAlgorithm_Sha1
	case "sha256":
		return spdx.HashAlgorithm_Sha256
	case "sha384":
		return spdx.HashAlgorithm_Sha384
	case "sha512":
		return spdx.HashAlgorithm_Sha512
	case "md5":
		return spdx.HashAlgorithm_Md5
	}
	return spdx.HashAlgorithm{}
}

func v3directorySourceMetadata(p spdx.AnyPackage) (any, string) {
	return source.DirectoryMetadata{
		Path: p.GetName(),
		Base: "",
	}, p.GetVersion()
}

func v3extractSourceFromNamespace(ns string) source.Description {
	u, err := url.Parse(ns)
	if err != nil {
		return source.Description{
			Metadata: nil,
		}
	}

	parts := strings.Split(u.Path, "/")
	for _, p := range parts {
		switch p {
		case helpers.InputFile:
			return source.Description{
				Metadata: source.FileMetadata{},
			}
		case helpers.InputImage:
			return source.Description{
				Metadata: source.ImageMetadata{},
			}
		case helpers.InputDirectory:
			return source.Description{
				Metadata: source.DirectoryMetadata{},
			}
		}
	}
	return source.Description{}
}

func v3findLinuxReleaseByPURL(doc *spdx.Document) *linux.Release {
	for _, p := range doc.Elements.Packages() {
		purlValue := v3findPURLValue(p)
		if purlValue == "" {
			continue
		}
		purl, err := packageurl.FromString(purlValue)
		if err != nil {
			log.Warnf("unable to parse purl: %s", purlValue)
			continue
		}
		distro := v3findQualifierValue(purl, pkg.PURLQualifierDistro)
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

func v3collectSyftPackages(s *sbom.SBOM, spdxIDMap map[string]any, doc *spdx.Document) {
	skipIDs := v3packageIDsToSkip(doc)
	for _, elementList := range []spdx.ElementList{doc.Elements, doc.RootElements} {
		for _, p := range elementList.Packages() {
			if p == nil || skipIDs.Has(p.GetID()) {
				continue
			}
			syftPkg := v3toSyftPackage(p)
			spdxIDMap[p.GetID()] = syftPkg
			s.Artifacts.Packages.Add(syftPkg)
		}
	}
}

func v3collectSyftFiles(s *sbom.SBOM, spdxIDMap map[string]any, doc *spdx.Document) {
	for _, elementList := range []spdx.ElementList{doc.Elements, doc.RootElements} {
		for _, f := range elementList.Files() {
			l := v3toSyftLocation(f)
			spdxIDMap[f.GetID()] = l

			s.Artifacts.FileMetadata[l.Coordinates] = v3toFileMetadata(f)
			s.Artifacts.FileDigests[l.Coordinates] = v3toFileDigests(f)
		}
	}
}

func v3toFileDigests(f spdx.AnyFile) (digests []file.Digest) {
	for _, digest := range f.GetVerifiedUsing() {
		h, _ := digest.(spdx.AnyHash)
		if h == nil {
			continue
		}
		digests = append(digests, file.Digest{
			Algorithm: v3fromChecksumAlgorithm(h.GetAlgorithm()),
			Value:     h.GetValue(),
		})
	}
	return digests
}

func v3fromChecksumAlgorithm(algorithm spdx.HashAlgorithm) string {
	// FIXME case statement with real mappings using type constants
	parts := strings.Split(algorithm.GetID(), "/")
	return strings.ToLower(parts[len(parts)-1])
}

func v3toFileMetadata(f spdx.AnyFile) (meta file.Metadata) {
	// FIXME Syft is currently lossy due to the SPDX 2.2.1 spec not supporting arbitrary mimetypes
	if f.GetContentType() != "" {
		meta.MIMEType = f.GetContentType()
	}
	return meta
}

func v3toSyftRelationships(spdxIDMap map[string]any, doc *spdx.Document) []artifact.Relationship {
	out := v3collectDocRelationships(spdxIDMap, doc)
	return out
}

func v3collectDocRelationships(spdxIDMap map[string]any, doc *spdx.Document) (out []artifact.Relationship) {
	for _, r := range doc.Elements.Relationships() {
		// FIXME what to do with r.RefA.DocumentRefID and r.RefA.SpecialID
		from := r.GetFrom()
		if from == nil {
			continue
		}
		if from.GetID() != "" { // && requireAndTrimPrefix(fromID, "DocumentRef-") != string(doc.SPDXIdentifier) {
			log.Debugf("ignoring relationship to external document: %+v", r)
			continue
		}
		a := spdxIDMap[from.GetID()]

		for _, to := range r.GetTo() {
			b := spdxIDMap[to.GetID()]
			from, fromOk := a.(pkg.Package)
			toPackage, toPackageOk := b.(pkg.Package)
			toLocation, toLocationOk := b.(file.Location)
			//nolint:staticcheck
			if !fromOk || !(toPackageOk || toLocationOk) {
				log.Debugf("unable to find valid relationship mapping from SPDX, ignoring: (from: %+v) (to: %+v)", a, b)
				continue
			}
			var to artifact.Identifiable
			var typ artifact.RelationshipType
			if toLocationOk {
				switch r.GetType() {
				case spdx.RelationshipType_Contains:
					typ = artifact.ContainsRelationship
					to = toLocation
				case spdx.RelationshipType_Other:
					// Encoding uses a specifically formatted comment...
					if strings.Index(r.GetComment(), string(artifact.EvidentByRelationship)) == 0 {
						typ = artifact.EvidentByRelationship
						to = toLocation
					}
				}
			} else {
				switch r.GetType() {
				case spdx.RelationshipType_DependsOn:
					typ = artifact.DependencyOfRelationship
					to = from
					from = toPackage
				case spdx.RelationshipType_Contains:
					typ = artifact.ContainsRelationship
					to = toPackage
				case spdx.RelationshipType_Other:
					// Encoding uses a specifically formatted comment...
					if strings.Index(r.GetComment(), string(artifact.OwnershipByFileOverlapRelationship)) == 0 {
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
	}
	return out
}

// collectPackageFileRelationships add relationships for direct files
// func collectPackageFileRelationships(spdxIDMap map[string]any, doc *spdx.Document) (out []artifact.Relationship) {
//	for _, p := range doc.Elements.Packages() {
//		packageID := getID(p)
//
//		a := spdxIDMap[string(packageID)]
//		from, fromOk := a.(pkg.Package)
//		if !fromOk {
//			continue
//		}
//		for _, f := range p.Files {
//			fileID := getID(f)
//
//			b := spdxIDMap[string(fileID)]
//			to, toLocationOk := b.(file.Location)
//			if !toLocationOk {
//				continue
//			}
//			out = append(out, artifact.Relationship{
//				From: from,
//				To:   to,
//				Type: artifact.ContainsRelationship,
//			})
//		}
//	}
//	return out
//}

func v3toSyftCoordinates(f spdx.AnyFile) file.Coordinates {
	const layerIDPrefix = "layerID: "
	var fileSystemID string
	if strings.Index(f.GetComment(), layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(f.GetComment(), layerIDPrefix)
	}
	if strings.Index(string(f.GetID()), layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(string(f.GetID()), layerIDPrefix)
	}
	return file.Coordinates{
		RealPath:     f.GetName(),
		FileSystemID: fileSystemID,
	}
}

func v3toSyftLocation(f spdx.AnyFile) file.Location {
	l := file.NewVirtualLocationFromCoordinates(v3toSyftCoordinates(f), f.GetName())
	return l
}

func v3requireAndTrimPrefix(val interface{}, prefix string) string {
	if v, ok := val.(string); ok {
		if i := strings.Index(v, prefix); i == 0 {
			return strings.Replace(v, prefix, "", 1)
		}
	}
	return ""
}

type v3pkgInfo struct {
	purl packageurl.PackageURL
	typ  pkg.Type
	lang pkg.Language
}

func (p *v3pkgInfo) v3qualifierValue(name string) string {
	return findQualifierValue(p.purl, name)
}

func v3findQualifierValue(purl packageurl.PackageURL, qualifier string) string {
	for _, q := range purl.Qualifiers {
		if q.Key == qualifier {
			return q.Value
		}
	}
	return ""
}

func v3extractPkgInfo(p spdx.AnyPackage) pkgInfo {
	pu := v3findPURLValue(p)
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

func v3toSyftPackage(p spdx.AnyPackage) pkg.Package {
	info := v3extractPkgInfo(p)
	sP := &pkg.Package{
		Type:     info.typ,
		Name:     p.GetName(),
		Version:  p.GetVersion(),
		Licenses: pkg.NewLicenseSet(v3parseSPDXLicenses(p)...),
		CPEs:     v3extractCPEs(p),
		PURL:     v3purlValue(info.purl),
		Language: info.lang,
		Metadata: v3extractMetadata(p, info),
	}

	internal.Backfill(sP)

	if p.GetID() != "" {
		// always prefer the IDs from the SBOM over derived IDs
		sP.OverrideID(artifact.ID(p.GetID()))
	} else {
		sP.SetID()
	}

	return *sP
}

func v3purlValue(purl packageurl.PackageURL) string {
	val := purl.String()
	if _, err := packageurl.FromString(val); err != nil {
		return ""
	}
	return val
}

func v3parseSPDXLicenses(p spdx.AnyPackage) []pkg.License {
	licenses := make([]pkg.License, 0)

	// FIXME -- where do licenses come from?
	//// concluded
	// if p.PackageLicenseConcluded != helpers.NOASSERTION && p.PackageLicenseConcluded != helpers.NONE && p.PackageLicenseConcluded != "" {
	//	l := pkg.NewLicenseWithContext(context.TODO(), cleanSPDXID(p.PackageLicenseConcluded))
	//	l.Type = license.Concluded
	//	licenses = append(licenses, l)
	//}
	//
	//// declared
	//if p.LicenseDeclared != helpers.NOASSERTION && p.PackageLicenseDeclared != helpers.NONE && p.PackageLicenseDeclared != "" {
	//	l := pkg.NewLicenseWithContext(context.TODO(), cleanSPDXID(p.PackageLicenseDeclared))
	//	l.Type = license.Declared
	//	licenses = append(licenses, l)
	//}

	return licenses
}

func v3cleanSPDXID(id string) string {
	return strings.TrimPrefix(id, helpers.LicenseRefPrefix)
}

//nolint:funlen
func v3extractMetadata(p spdx.AnyPackage, info pkgInfo) any {
	arch := info.qualifierValue(pkg.PURLQualifierArch)
	upstreamValue := info.qualifierValue(pkg.PURLQualifierUpstream)
	upstream := strings.SplitN(upstreamValue, "@", 2)
	upstreamName := upstream[0]
	upstreamVersion := ""
	if len(upstream) > 1 {
		upstreamVersion = upstream[1]
	}
	supplier := ""
	if p.GetSuppliedBy() != nil {
		supplier = v3agentString(p.GetSuppliedBy())
	}
	originator := ""
	if len(p.GetOriginatedBy()) > 0 {
		// FIXME multiple
		originator = v3agentString(p.GetOriginatedBy()[0])
	}
	switch info.typ {
	case pkg.ApkPkg:
		return pkg.ApkDBEntry{
			Package:       p.GetName(),
			OriginPackage: upstreamName,
			Maintainer:    supplier,
			Version:       p.GetVersion(),
			Architecture:  arch,
			URL:           string(p.GetHomePage()),
			Description:   p.GetDescription(),
		}
	case pkg.RpmPkg:
		converted, err := strconv.Atoi(info.qualifierValue(pkg.PURLQualifierEpoch))
		var epoch *int
		if err != nil {
			epoch = nil
		} else {
			epoch = &converted
		}
		return pkg.RpmDBEntry{
			Name:      p.GetName(),
			Version:   p.GetVersion(),
			Epoch:     epoch,
			Arch:      arch,
			SourceRpm: upstreamValue,
			Vendor:    originator,
		}
	case pkg.DebPkg:
		return pkg.DpkgDBEntry{
			Package:       p.GetName(),
			Source:        upstreamName,
			Version:       p.GetVersion(),
			SourceVersion: upstreamVersion,
			Architecture:  arch,
			Maintainer:    originator,
		}
	case pkg.JavaPkg:
		var digests []file.Digest
		for _, value := range p.GetVerifiedUsing() {
			h, _ := value.(spdx.AnyHash)
			if h != nil {
				digests = append(digests, file.Digest{Algorithm: v3fromChecksumAlgorithm(h.GetAlgorithm()), Value: h.GetValue()})
			}
		}
		return pkg.JavaArchive{
			ArchiveDigests: digests,
		}
	case pkg.GoModulePkg:
		var h1Digest string
		for _, value := range p.GetVerifiedUsing() {
			h, _ := value.(spdx.AnyHash)
			if h == nil {
				continue
			}
			digest, err := helpers.HDigestFromSHA(v3fromChecksumAlgorithm(h.GetAlgorithm()), h.GetValue())
			if err != nil {
				log.Debugf("invalid h1digest: %v %v", value, err)
				continue
			}
			h1Digest = digest
			break
		}
		return pkg.GolangBinaryBuildinfoEntry{
			H1Digest: h1Digest,
		}
	}
	return nil
}

func v3agentString(agent spdx.AnyAgent) string {
	switch o := agent.(type) {
	case spdx.AnyOrganization:
		return o.GetName()
	case spdx.AnyPerson:
		return o.GetName()
	}
	return ""
}

func v3findPURLValue(p spdx.AnyPackage) string {
	for _, r := range p.GetExternalIdentifiers() {
		if r.GetType() == spdx.ExternalIdentifierType_PackageURL {
			for _, l := range r.GetIdentifierLocators() {
				// FIXME multiple values
				return string(l)
			}
		}
	}
	return ""
}

func v3extractCPEs(p spdx.AnyPackage) (cpes []cpe.CPE) {
	for _, r := range p.GetExternalIdentifiers() {
		if r.GetType() == spdx.ExternalIdentifierType_Cpe23 || r.GetType() == spdx.ExternalIdentifierType_Cpe22 {
			for _, l := range r.GetIdentifierLocators() {
				c, err := cpe.New(string(l), cpe.DeclaredSource)
				if err != nil {
					log.Warnf("unable to extract SPDX CPE=%q: %+v", l, err)
					continue
				}
				cpes = append(cpes, c)
			}
		}
	}
	return cpes
}

// v3packageIDsToSkip returns a set of packageIDs that should not be imported
func v3packageIDsToSkip(doc *spdx.Document) *strset.Set {
	skipIDs := strset.New()
	for _, r := range doc.Elements.Relationships() {
		if r != nil && r.GetFrom() != nil && r.GetType() == spdx.RelationshipType_Generates {
			skipIDs.Add(r.GetFrom().GetID()) // flipped from GENERATED_FROM
		}
	}
	return skipIDs
}
