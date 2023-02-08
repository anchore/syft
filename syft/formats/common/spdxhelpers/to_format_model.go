//nolint:gosec // sha1 is used as a required hash function for SPDX, not a crypto function
package spdxhelpers

import (
	"crypto/sha1"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/common/util"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	noAssertion = "NOASSERTION"
)

// ToFormatModel creates and populates a new SPDX document struct that follows the SPDX 2.3
// spec from the given SBOM model.
//
//nolint:funlen
func ToFormatModel(s sbom.SBOM) *spdx.Document {
	name, namespace := DocumentNameAndNamespace(s.Source)
	relationships := toRelationships(s.RelationshipsSorted())

	// for valid SPDX we need a document describes relationship
	// TODO: remove this placeholder after deciding on correct behavior
	// for the primary package purpose field:
	// https://spdx.github.io/spdx-spec/v2.3/package-information/#724-primary-package-purpose-field
	documentDescribesRelationship := &spdx.Relationship{
		RefA: spdx.DocElementID{
			ElementRefID: "DOCUMENT",
		},
		Relationship: string(DescribesRelationship),
		RefB: spdx.DocElementID{
			ElementRefID: "DOCUMENT",
		},
		RelationshipComment: "",
	}

	relationships = append(relationships, documentDescribesRelationship)

	return &spdx.Document{
		// 6.1: SPDX Version; should be in the format "SPDX-x.x"
		// Cardinality: mandatory, one
		SPDXVersion: spdx.Version,

		// 6.2: Data License; should be "CC0-1.0"
		// Cardinality: mandatory, one
		DataLicense: spdx.DataLicense,

		// 6.3: SPDX Identifier; should be "DOCUMENT" to represent mandatory identifier of SPDXRef-DOCUMENT
		// Cardinality: mandatory, one
		SPDXIdentifier: "DOCUMENT",

		// 6.4: Document Name
		// Cardinality: mandatory, one
		DocumentName: name,

		// 6.5: Document Namespace
		// Cardinality: mandatory, one
		// Purpose: Provide an SPDX document specific namespace as a unique absolute Uniform Resource
		// Identifier (URI) as specified in RFC-3986, with the exception of the ‘#’ delimiter. The SPDX
		// Document URI cannot contain a URI "part" (e.g. the "#" character), since the ‘#’ is used in SPDX
		// element URIs (packages, files, snippets, etc) to separate the document namespace from the
		// element’s SPDX identifier. Additionally, a scheme (e.g. “https:”) is required.

		// The URI must be unique for the SPDX document including the specific version of the SPDX document.
		// If the SPDX document is updated, thereby creating a new version, a new URI for the updated
		// document must be used. There can only be one URI for an SPDX document and only one SPDX document
		// for a given URI.

		// Note that the URI does not have to be accessible. It is only intended to provide a unique ID.
		// In many cases, the URI will point to a web accessible document, but this should not be assumed
		// to be the case.

		DocumentNamespace: namespace,

		// 6.6: External Document References
		// Cardinality: optional, one or many
		ExternalDocumentReferences: nil,

		// 6.11: Document Comment
		// Cardinality: optional, one
		DocumentComment: "",

		CreationInfo: &spdx.CreationInfo{
			// 6.7: License List Version
			// Cardinality: optional, one
			LicenseListVersion: spdxlicense.Version,

			// 6.8: Creators: may have multiple keys for Person, Organization
			//      and/or Tool
			// Cardinality: mandatory, one or many
			Creators: []spdx.Creator{
				{
					Creator:     "Anchore, Inc",
					CreatorType: "Organization",
				},
				{
					Creator:     internal.ApplicationName + "-" + s.Descriptor.Version,
					CreatorType: "Tool",
				},
			},

			// 6.9: Created: data format YYYY-MM-DDThh:mm:ssZ
			// Cardinality: mandatory, one
			Created: time.Now().UTC().Format(time.RFC3339),

			// 6.10: Creator Comment
			// Cardinality: optional, one
			CreatorComment: "",
		},
		Packages:      toPackages(s.Artifacts.PackageCatalog, s),
		Files:         toFiles(s),
		Relationships: relationships,
		OtherLicenses: toOtherLicenses(s.Artifacts.PackageCatalog),
	}
}

func toSPDXID(identifiable artifact.Identifiable) spdx.ElementID {
	id := ""
	if p, ok := identifiable.(pkg.Package); ok {
		id = SanitizeElementID(fmt.Sprintf("Package-%+v-%s-%s", p.Type, p.Name, p.ID()))
	} else {
		id = string(identifiable.ID())
	}
	// NOTE: the spdx libraries prepend SPDXRef-, so we don't do it here
	return spdx.ElementID(id)
}

// packages populates all Package Information from the package Catalog (see https://spdx.github.io/spdx-spec/3-package-information/)
//
//nolint:funlen
func toPackages(catalog *pkg.Catalog, sbom sbom.SBOM) (results []*spdx.Package) {
	for _, p := range catalog.Sorted() {
		// name should be guaranteed to be unique, but semantically useful and stable
		id := toSPDXID(p)

		// If the Concluded License is not the same as the Declared License, a written explanation should be provided
		// in the Comments on License field (section 7.16). With respect to NOASSERTION, a written explanation in
		// the Comments on License field (section 7.16) is preferred.
		license := License(p)

		// two ways to get filesAnalyzed == true:
		// 1. syft has generated a sha1 digest for the package itself - usually in the java cataloger
		// 2. syft has generated a sha1 digest for the package's contents
		packageChecksums, filesAnalyzed := toPackageChecksums(p)

		packageVerificationCode := newPackageVerificationCode(p, sbom)
		if packageVerificationCode != nil {
			filesAnalyzed = true
		}

		// invalid SPDX document state
		if filesAnalyzed && packageVerificationCode == nil {
			// this is an invalid document state
			// we reset the filesAnalyzed flag to false to avoid
			// cases where a package digest was generated but there was
			// not enough metadata to generate a verification code regarding the files
			filesAnalyzed = false
		}

		results = append(results, &spdx.Package{
			// NOT PART OF SPEC
			// flag: does this "package" contain files that were in fact "unpackaged",
			// e.g. included directly in the Document without being in a Package?
			IsUnpackaged: false,

			// 7.1: Package Name
			// Cardinality: mandatory, one
			PackageName: p.Name,

			// 7.2: Package SPDX Identifier: "SPDXRef-[idstring]"
			// Cardinality: mandatory, one
			PackageSPDXIdentifier: id,

			// 7.3: Package Version
			// Cardinality: optional, one
			PackageVersion: p.Version,

			// 7.4: Package File Name
			// Cardinality: optional, one
			PackageFileName: "",

			// 7.5: Package Supplier: may have single result for either Person or Organization,
			//                        or NOASSERTION
			// Cardinality: optional, one

			// 7.6: Package Originator: may have single result for either Person or Organization,
			//                          or NOASSERTION
			// Cardinality: optional, one
			PackageSupplier: nil,

			PackageOriginator: toPackageOriginator(p),

			// 7.7: Package Download Location
			// Cardinality: mandatory, one
			// NONE if there is no download location whatsoever.
			// NOASSERTION if:
			//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
			//   (ii) the SPDX file creator has made no attempt to determine this field; or
			//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).
			PackageDownloadLocation: DownloadLocation(p),

			// 7.8: FilesAnalyzed
			// Cardinality: optional, one; default value is "true" if omitted

			// Purpose: Indicates whether the file content of this package has been available for or subjected to
			// analysis when creating the SPDX document. If false, indicates packages that represent metadata or
			// URI references to a project, product, artifact, distribution or a component. If false, the package
			// must not contain any files.

			// Intent: A package can refer to a project, product, artifact, distribution or a component that is
			// external to the SPDX document.
			FilesAnalyzed: filesAnalyzed,
			// NOT PART OF SPEC: did FilesAnalyzed tag appear?
			IsFilesAnalyzedTagPresent: true,

			// 7.9: Package Verification Code
			// Cardinality: optional, one if filesAnalyzed is true / omitted;
			//              zero (must be omitted) if filesAnalyzed is false
			PackageVerificationCode: packageVerificationCode,

			// 7.10: Package Checksum: may have keys for SHA1, SHA256 and/or MD5
			// Cardinality: optional, one or many

			// 7.10.1 Purpose: Provide an independently reproducible mechanism that permits unique identification of
			// a specific package that correlates to the data in this SPDX file. This identifier enables a recipient
			// to determine if any file in the original package has been changed. If the SPDX file is to be included
			// in a package, this value should not be calculated. The SHA-1 algorithm will be used to provide the
			// checksum by default.
			PackageChecksums: packageChecksums,

			// 7.11: Package Home Page
			// Cardinality: optional, one
			PackageHomePage: Homepage(p),

			// 7.12: Source Information
			// Cardinality: optional, one
			PackageSourceInfo: SourceInfo(p),

			// 7.13: Concluded License: SPDX License Expression, "NONE" or "NOASSERTION"
			// Cardinality: mandatory, one
			// Purpose: Contain the license the SPDX file creator has concluded as governing the
			// package or alternative values, if the governing license cannot be determined.
			PackageLicenseConcluded: license,

			// 7.14: All Licenses Info from Files: SPDX License Expression, "NONE" or "NOASSERTION"
			// Cardinality: mandatory, one or many if filesAnalyzed is true / omitted;
			//              zero (must be omitted) if filesAnalyzed is false
			PackageLicenseInfoFromFiles: nil,

			// 7.15: Declared License: SPDX License Expression, "NONE" or "NOASSERTION"
			// Cardinality: mandatory, one
			// Purpose: List the licenses that have been declared by the authors of the package.
			// Any license information that does not originate from the package authors, e.g. license
			// information from a third party repository, should not be included in this field.
			PackageLicenseDeclared: license,

			// 7.16: Comments on License
			// Cardinality: optional, one
			PackageLicenseComments: "",

			// 7.17: Copyright Text: copyright notice(s) text, "NONE" or "NOASSERTION"
			// Cardinality: mandatory, one
			// Purpose: IdentifyFormat the copyright holders of the package, as well as any dates present. This will be a free form text field extracted from package information files. The options to populate this field are limited to:
			//
			// Any text related to a copyright notice, even if not complete;
			// NONE if the package contains no copyright information whatsoever; or
			// NOASSERTION, if
			//   (i) the SPDX document creator has made no attempt to determine this field; or
			//   (ii) the SPDX document creator has intentionally provided no information (no meaning should be implied by doing so).
			//
			PackageCopyrightText: noAssertion,

			// 7.18: Package Summary Description
			// Cardinality: optional, one
			PackageSummary: "",

			// 7.19: Package Detailed Description
			// Cardinality: optional, one
			PackageDescription: Description(p),

			// 7.20: Package Comment
			// Cardinality: optional, one
			PackageComment: "",

			// 7.21: Package External Reference
			// Cardinality: optional, one or many
			PackageExternalReferences: formatSPDXExternalRefs(p),

			// 7.22: Package External Reference Comment
			// Cardinality: conditional (optional, one) for each External Reference
			// contained within PackageExternalReference2_1 struct, if present

			// 7.23: Package Attribution Text
			// Cardinality: optional, one or many
			PackageAttributionTexts: nil,
		})
	}
	return results
}

func toPackageChecksums(p pkg.Package) ([]spdx.Checksum, bool) {
	filesAnalyzed := false
	var checksums []spdx.Checksum
	switch meta := p.Metadata.(type) {
	// we generate digest for some Java packages
	// spdx.github.io/spdx-spec/package-information/#710-package-checksum-field
	case pkg.JavaMetadata:
		// if syft has generated the digest here then filesAnalyzed is true
		if len(meta.ArchiveDigests) > 0 {
			filesAnalyzed = true
			for _, digest := range meta.ArchiveDigests {
				algo := strings.ToUpper(digest.Algorithm)
				checksums = append(checksums, spdx.Checksum{
					Algorithm: spdx.ChecksumAlgorithm(algo),
					Value:     digest.Value,
				})
			}
		}
	case pkg.GolangBinMetadata:
		// because the H1 digest is found in the Golang metadata we cannot claim that the files were analyzed
		algo, hexStr, err := util.HDigestToSHA(meta.H1Digest)
		if err != nil {
			log.Debugf("invalid h1digest: %s: %v", meta.H1Digest, err)
			break
		}
		algo = strings.ToUpper(algo)
		checksums = append(checksums, spdx.Checksum{
			Algorithm: spdx.ChecksumAlgorithm(algo),
			Value:     hexStr,
		})
	}
	return checksums, filesAnalyzed
}

func toPackageOriginator(p pkg.Package) *spdx.Originator {
	kind, originator := Originator(p)
	if kind == "" || originator == "" {
		return nil
	}
	return &spdx.Originator{
		Originator:     originator,
		OriginatorType: kind,
	}
}

func formatSPDXExternalRefs(p pkg.Package) (refs []*spdx.PackageExternalReference) {
	for _, ref := range ExternalRefs(p) {
		refs = append(refs, &spdx.PackageExternalReference{
			Category:           string(ref.ReferenceCategory),
			RefType:            string(ref.ReferenceType),
			Locator:            ref.ReferenceLocator,
			ExternalRefComment: ref.Comment,
		})
	}
	return refs
}

func toRelationships(relationships []artifact.Relationship) (result []*spdx.Relationship) {
	for _, r := range relationships {
		exists, relationshipType, comment := lookupRelationship(r.Type)

		if !exists {
			log.Debugf("unable to convert relationship to SPDX, dropping: %+v", r)
			continue
		}

		// FIXME: we are only currently including Package -> * relationships
		if _, ok := r.From.(pkg.Package); !ok {
			log.Debugf("skipping non-package relationship: %+v", r)
			continue
		}

		result = append(result, &spdx.Relationship{
			RefA: spdx.DocElementID{
				ElementRefID: toSPDXID(r.From),
			},
			Relationship: string(relationshipType),
			RefB: spdx.DocElementID{
				ElementRefID: toSPDXID(r.To),
			},
			RelationshipComment: comment,
		})
	}
	return result
}

func lookupRelationship(ty artifact.RelationshipType) (bool, RelationshipType, string) {
	switch ty {
	case artifact.ContainsRelationship:
		return true, ContainsRelationship, ""
	case artifact.DependencyOfRelationship:
		return true, DependencyOfRelationship, ""
	case artifact.OwnershipByFileOverlapRelationship:
		return true, OtherRelationship, fmt.Sprintf("%s: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by", ty)
	}
	return false, "", ""
}

func toFiles(s sbom.SBOM) (results []*spdx.File) {
	artifacts := s.Artifacts

	for _, coordinates := range s.AllCoordinates() {
		var metadata *source.FileMetadata
		if metadataForLocation, exists := artifacts.FileMetadata[coordinates]; exists {
			metadata = &metadataForLocation
		}

		var digests []file.Digest
		if digestsForLocation, exists := artifacts.FileDigests[coordinates]; exists {
			digests = digestsForLocation
		}

		// if we don't have any metadata or digests for this location
		// then the file is most likely a symlink or non-regular file
		// for now we include a 0 sha1 digest as requested by the spdx spec
		// TODO: update location code in core SBOM so that we can map complex links
		// back to their real file digest location.
		if len(digests) == 0 {
			digests = append(digests, file.Digest{Algorithm: "sha1", Value: "0000000000000000000000000000000000000000"})
		}

		// TODO: add file classifications (?) and content as a snippet

		var comment string
		if coordinates.FileSystemID != "" {
			comment = fmt.Sprintf("layerID: %s", coordinates.FileSystemID)
		}

		results = append(results, &spdx.File{
			FileSPDXIdentifier: toSPDXID(coordinates),
			FileComment:        comment,
			// required, no attempt made to determine license information
			LicenseConcluded: noAssertion,
			Checksums:        toFileChecksums(digests),
			FileName:         coordinates.RealPath,
			FileTypes:        toFileTypes(metadata),
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].FileName == results[j].FileName {
			return results[i].FileSPDXIdentifier < results[j].FileSPDXIdentifier
		}
		return results[i].FileName < results[j].FileName
	})
	return results
}

func toFileChecksums(digests []file.Digest) (checksums []spdx.Checksum) {
	checksums = make([]spdx.Checksum, 0, len(digests))
	for _, digest := range digests {
		checksums = append(checksums, spdx.Checksum{
			Algorithm: toChecksumAlgorithm(digest.Algorithm),
			Value:     digest.Value,
		})
	}
	return checksums
}

func toChecksumAlgorithm(algorithm string) spdx.ChecksumAlgorithm {
	// this needs to be an uppercase version of our algorithm
	return spdx.ChecksumAlgorithm(strings.ToUpper(algorithm))
}

func toFileTypes(metadata *source.FileMetadata) (ty []string) {
	if metadata == nil {
		return nil
	}

	mimeTypePrefix := strings.Split(metadata.MIMEType, "/")[0]
	switch mimeTypePrefix {
	case "image":
		ty = append(ty, string(ImageFileType))
	case "video":
		ty = append(ty, string(VideoFileType))
	case "application":
		ty = append(ty, string(ApplicationFileType))
	case "text":
		ty = append(ty, string(TextFileType))
	case "audio":
		ty = append(ty, string(AudioFileType))
	}

	if internal.IsExecutable(metadata.MIMEType) {
		ty = append(ty, string(BinaryFileType))
	}

	if internal.IsArchive(metadata.MIMEType) {
		ty = append(ty, string(ArchiveFileType))
	}

	// TODO: add support for source, spdx, and documentation file types
	if len(ty) == 0 {
		ty = append(ty, string(OtherFileType))
	}

	return ty
}

func toOtherLicenses(catalog *pkg.Catalog) []*spdx.OtherLicense {
	licenses := map[string]bool{}
	for _, pkg := range catalog.Sorted() {
		for _, license := range pkg.Licenses.Elements() {
			if strings.HasPrefix(license, spdxlicense.LicenseRefPrefix) {
				licenses[license] = true
			}
		}
	}
	var result []*spdx.OtherLicense
	for license := range licenses {
		// separate the actual ID from the prefix
		name := strings.TrimPrefix(license, spdxlicense.LicenseRefPrefix)
		result = append(result, &spdx.OtherLicense{
			LicenseIdentifier: license,
			LicenseName:       name,
			ExtractedText:     NONE, // we probably should have some extracted text here, but this is good enough for now
		})
	}
	return result
}

// TODO: handle SPDX excludes file case
// f file is an "excludes" file, skip it /* exclude SPDX analysis file(s) */
// see: https://spdx.github.io/spdx-spec/v2.3/package-information/#79-package-verification-code-field
// the above link contains the SPDX algorithm for a package verification code
func newPackageVerificationCode(p pkg.Package, sbom sbom.SBOM) *spdx.PackageVerificationCode {
	// key off of the contains relationship;
	// spdx validator will fail if a package claims to contain a file but no sha1 provided
	// if a sha1 for a file is provided then the validator will fail if the package does not have
	// a package verification code
	coordinates := sbom.CoordinatesForPackage(p, artifact.ContainsRelationship)
	var digests []file.Digest
	for _, c := range coordinates {
		digest := sbom.Artifacts.FileDigests[c]
		if len(digest) == 0 {
			continue
		}

		var d file.Digest
		for _, digest := range digest {
			if digest.Algorithm == "sha1" {
				d = digest
				break
			}
		}
		digests = append(digests, d)
	}

	if len(digests) == 0 {
		return nil
	}

	// sort templist in ascending order by SHA1 value
	sort.SliceStable(digests, func(i, j int) bool {
		return digests[i].Value < digests[j].Value
	})

	// filelist = templist with "/n"s removed. /* ordered sequence of SHA1 values with no separators
	var b strings.Builder
	for _, digest := range digests {
		b.WriteString(digest.Value)
	}

	//nolint:gosec
	hasher := sha1.New()
	_, _ = hasher.Write([]byte(b.String()))
	return &spdx.PackageVerificationCode{
		// 7.9.1: Package Verification Code Value
		// Cardinality: mandatory, one
		Value: fmt.Sprintf("%+x", hasher.Sum(nil)),
	}
}
