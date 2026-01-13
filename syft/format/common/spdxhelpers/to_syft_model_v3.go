package spdxhelpers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	spdx "github.com/spdx/tools-golang/spdx/v3/v3_0"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal"
	"github.com/anchore/syft/syft/format/internal/spdxutil/helpers"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func ToSyftModelV3(doc *spdx.Document) (*sbom.SBOM, error) {
	if doc == nil {
		return nil, errors.New("cannot convert SPDX document to Syft model because document is nil")
	}

	spdxMap := ptrMap[any]{}

	s := &sbom.SBOM{
		Source: v3extractSource(spdxMap, doc),
		Artifacts: sbom.Artifacts{
			Packages:          pkg.NewCollection(),
			FileMetadata:      map[file.Coordinates]file.Metadata{},
			FileDigests:       map[file.Coordinates][]file.Digest{},
			LinuxDistribution: v3findLinuxReleaseByPURL(doc),
		},
	}

	relationships := v3relationshipMap(doc)

	v3collectSyftPackages(s, spdxMap, relationships, doc)

	v3collectSyftFiles(s, spdxMap, doc)

	s.Relationships = v3toSyftRelationships(spdxMap, doc)

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
	for _, p := range doc.GetRootElements().Packages() {
		out = append(out, p)
	}
	for _, s := range doc.GetRootElements().SBOMs() {
		for _, p := range s.GetRootElements().Packages() {
			out = append(out, p)
		}
	}
	return
}

func v3extractSource(spdxMap ptrMap[any], doc *spdx.Document) source.Description {
	namespace := doc.ID
	if namespace == "" && len(doc.NamespaceMaps) > 0 {
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

	panicIfErr(spdxMap.Set(p, src))

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
	if len(p.GetVerifiedUsing().Hashes()) > 0 {
		h := p.GetVerifiedUsing().Hashes()[0]
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
	typeRegex := regexp.MustCompile("DocumentRoot-([^-]+)-.*$")
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

	supplier := ""
	if p.GetSuppliedBy() != nil {
		supplier = p.GetSuppliedBy().GetName()
	}

	return source.Description{
		ID:       p.GetID(),
		Name:     p.GetName(),
		Version:  version,
		Supplier: supplier,
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
	for _, d := range p.GetVerifiedUsing().Hashes() {
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

func v3directorySourceMetadata(p spdx.AnyPackage) (any, string) {
	return source.DirectoryMetadata{
		Path: p.GetName(),
		Base: "",
	}, p.GetVersion()
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

func v3collectSyftPackages(s *sbom.SBOM, spdxMap ptrMap[any], relationships ptrMap[[]spdx.AnyRelationship], doc *spdx.Document) {
	skipIDs := v3packageIDsToSkip(doc)
	found := ptrMap[struct{}]{}
	for _, elementList := range []spdx.ElementList{doc.Elements, doc.RootElements} {
		for _, p := range elementList.Packages() {
			if p == nil || skipIDs.Has(p.GetID()) || found.Has(p.GetID()) {
				continue
			}
			panicIfErr(found.Set(p, struct{}{}))
			syftPkg := v3toSyftPackage(relationships, p)
			panicIfErr(spdxMap.Set(p, syftPkg))
			s.Artifacts.Packages.Add(syftPkg)
		}
	}
}

func v3collectSyftFiles(s *sbom.SBOM, spdxMap ptrMap[any], doc *spdx.Document) {
	found := ptrMap[struct{}]{}
	for _, elementList := range []spdx.ElementList{doc.Elements, doc.RootElements} {
		for _, f := range elementList.Files() {
			if found.Has(f) {
				continue
			}
			panicIfErr(found.Set(f, struct{}{}))
			l := v3toSyftLocation(f)
			panicIfErr(spdxMap.Set(f, l))

			s.Artifacts.FileMetadata[l.Coordinates] = v3toFileMetadata(f)
			s.Artifacts.FileDigests[l.Coordinates] = v3toFileDigests(f)
		}
	}
}

func v3toFileDigests(f spdx.AnyFile) (digests []file.Digest) {
	for _, h := range f.GetVerifiedUsing().Hashes() {
		digests = append(digests, file.Digest{
			Algorithm: v3fromChecksumAlgorithm(h.GetAlgorithm()),
			Value:     h.GetValue(),
		})
	}
	return digests
}

func v3fromChecksumAlgorithm(algorithm spdx.HashAlgorithm) string {
	// it might be better to have a specific case statement with constants
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

func v3toSyftRelationships(spdxMap ptrMap[any], doc *spdx.Document) []artifact.Relationship {
	out := v3collectDocRelationships(spdxMap, doc)

	return out
}

//nolint:gocognit
func v3collectDocRelationships(spdxMap ptrMap[any], doc *spdx.Document) (out []artifact.Relationship) {
	for _, r := range doc.Elements.Relationships() {
		from := r.GetFrom()
		if from == nil || from.GetID() == "" {
			log.Debugf("ignoring relationship to external document: %+v", r)
			continue
		}
		a, err := spdxMap.Get(from)
		panicIfErr(err)

		for _, to := range r.GetTo() {
			b, err := spdxMap.Get(to)
			panicIfErr(err)
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

func v3toSyftCoordinates(f spdx.AnyFile) file.Coordinates {
	const layerIDPrefix = "layerID: "
	var fileSystemID string
	if strings.Index(f.GetComment(), layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(f.GetComment(), layerIDPrefix)
	}
	if strings.Index(f.GetID(), layerIDPrefix) == 0 {
		fileSystemID = strings.TrimPrefix(f.GetID(), layerIDPrefix)
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

func v3toSyftPackage(relationships ptrMap[[]spdx.AnyRelationship], p spdx.AnyPackage) pkg.Package {
	info := v3extractPkgInfo(p)
	sP := &pkg.Package{
		Type:     info.typ,
		Name:     p.GetName(),
		Version:  p.GetVersion(),
		Licenses: pkg.NewLicenseSet(v3parseSPDXLicenses(relationships, p)...),
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

func v3parseSPDXLicenses(relationships ptrMap[[]spdx.AnyRelationship], p spdx.AnyPackage) []pkg.License {
	licenses := make([]pkg.License, 0)

	// licenses are defined with relationships in SPDX 3, see:
	// https://github.com/spdx/tools-golang/blob/spdx3/spdx/v3/v3_0/convert.go#L536
	rels, err := relationships.Get(p)
	panicIfErr(err)
	for _, r := range rels {
		if r.GetType() == spdx.RelationshipType_HasConcludedLicense {
			licenses = append(licenses, v3toSyftLicenses(license.Concluded, r.GetTo().Licenses()...)...)
		}
		if r.GetType() == spdx.RelationshipType_HasDeclaredLicense {
			licenses = append(licenses, v3toSyftLicenses(license.Declared, r.GetTo().Licenses()...)...)
		}
	}

	return licenses
}

func v3toSyftLicenses(licenseType license.Type, licenses ...spdx.AnyLicense) []pkg.License {
	var out []pkg.License
	for _, lic := range licenses {
		switch li := lic.(type) {
		case spdx.AnyLicenseExpression:
			l := pkg.NewLicenseWithContext(context.TODO(), li.GetLicenseExpression())
			l.Type = licenseType
			out = append(out, l)
		case spdx.AnyListedLicense:
			l := pkg.NewLicenseWithContext(context.TODO(), li.GetName())
			l.Type = licenseType
			out = append(out, l)
		case spdx.AnyCustomLicense:
			l := pkg.NewLicenseWithContext(context.TODO(), li.GetText())
			l.Type = licenseType
			out = append(out, l)
		default:
			log.Debugf("skipping SPDX license during import: %#v", lic)
		}
	}
	return out
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
func v3packageIDsToSkip(doc *spdx.Document) ptrMap[struct{}] {
	skipIDs := ptrMap[struct{}]{}
	for _, r := range doc.Elements.Relationships() {
		if r != nil && r.GetFrom() != nil && r.GetType() == spdx.RelationshipType_Generates {
			panicIfErr(skipIDs.Set(r.GetFrom(), struct{}{})) // flipped from GENERATED_FROM
		}
	}
	return skipIDs
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

func v3relationshipMap(doc *spdx.Document) ptrMap[[]spdx.AnyRelationship] {
	relationships := ptrMap[[]spdx.AnyRelationship]{}
	for _, r := range doc.Elements.Relationships() {
		rels, err := relationships.Get(r.GetFrom())
		panicIfErr(err)
		panicIfErr(relationships.Set(r.GetFrom(), append(rels, r)))
	}
	return relationships
}

// SPDX 3 values are stored as pointers and there is a distinct possibility that IDs will be blank if they were blank node IDs in the document

type ptrMap[T any] map[reflect.Value]T

func (s ptrMap[T]) Set(k any, v T) error {
	ptr, err := ptrTo(k)
	if err != nil {
		return err
	}
	s[ptr] = v
	return nil
}

func (s ptrMap[T]) Get(k any) (T, error) {
	ptr, err := ptrTo(k)
	if err != nil {
		var t T
		return t, err
	}
	return s[ptr], nil
}

func (s ptrMap[T]) Remove(k any) error {
	ptr, err := ptrTo(k)
	if err != nil {
		return err
	}
	delete(s, ptr)
	return nil
}

func (s ptrMap[T]) Has(k any) bool {
	ptr, err := ptrTo(k)
	if err != nil {
		return false
	}
	_, ok := s[ptr]
	return ok
}

func ptrTo(k any) (reflect.Value, error) {
	rv := reflect.ValueOf(k)
	if rv.Kind() != reflect.Pointer {
		return rv, fmt.Errorf("value is not a pointer: %#v", k)
	}
	return rv, nil
}

func panicIfErr(e error) {
	if e != nil {
		panic(e)
	}
}
