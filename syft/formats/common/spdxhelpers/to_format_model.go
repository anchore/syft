package spdxhelpers

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spdx/tools-golang/spdx/common"
	spdx "github.com/spdx/tools-golang/spdx/v2_3"

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
	spdxVersion = "SPDX-2.3"
	noAssertion = "NOASSERTION"
)

// ToFormatModel creates and populates a new SPDX document struct that follows the SPDX 2.3
// spec from the given SBOM model.
//
//nolint:funlen
func ToFormatModel(s sbom.SBOM) *spdx.Document {
	name, namespace := DocumentNameAndNamespace(s.Source)

	return &spdx.Document{
		// 2.1: SPDX Version; should be in the format "SPDX-2.3"
		// Cardinality: mandatory, one
		SPDXVersion: spdxVersion,

		// 2.2: Data License; should be "CC0-1.0"
		// Cardinality: mandatory, one
		DataLicense: "CC0-1.0",

		// 2.3: SPDX Identifier; should be "DOCUMENT" to represent mandatory identifier of SPDXRef-DOCUMENT
		// Cardinality: mandatory, one
		SPDXIdentifier: "DOCUMENT",

		// 2.4: Document Name
		// Cardinality: mandatory, one
		DocumentName: name,

		// 2.5: Document Namespace
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

		// 2.6: External Document References
		// Cardinality: optional, one or many
		ExternalDocumentReferences: nil,

		// 2.11: Document Comment
		// Cardinality: optional, one
		DocumentComment: "",

		CreationInfo: &spdx.CreationInfo{
			// 2.7: License List Version
			// Cardinality: optional, one
			LicenseListVersion: spdxlicense.Version,

			// 2.8: Creators: may have multiple keys for Person, Organization
			//      and/or Tool
			// Cardinality: mandatory, one or many
			Creators: []common.Creator{
				{
					Creator:     "Anchore, Inc",
					CreatorType: "Organization",
				},
				{
					Creator:     internal.ApplicationName + "-" + s.Descriptor.Version,
					CreatorType: "Tool",
				},
			},

			// 2.9: Created: data format YYYY-MM-DDThh:mm:ssZ
			// Cardinality: mandatory, one
			Created: time.Now().UTC().Format(time.RFC3339),

			// 2.10: Creator Comment
			// Cardinality: optional, one
			CreatorComment: "",
		},
		Packages:      toPackages(s.Artifacts.PackageCatalog, s.Relationships),
		Files:         toFiles(s),
		Relationships: toRelationships(s.Relationships),
	}
}

func filesForPackage(packageSpdxID common.ElementID, relationships []artifact.Relationship) (files []*spdx.File) {
	for _, relationship := range relationships {
		if relationship.Type != artifact.ContainsRelationship {
			continue
		}

		if _, ok := relationship.From.(pkg.Package); !ok {
			continue
		}

		if _, ok := relationship.To.(source.Coordinates); !ok {
			continue
		}

		from := toSPDXID(relationship.From)
		if from == packageSpdxID {
			to := toSPDXID(relationship.To)
			files = append(files, &spdx.File{
				// TODO should we fill out more information here?
				FileSPDXIdentifier: to,
			})
		}
	}
	return files
}

func toSPDXID(v interface{}) common.ElementID {
	id := ""
	switch v := v.(type) {
	case pkg.Package:
		id = SanitizeElementID(fmt.Sprintf("Package-%+v-%s-%s", v.Type, v.Name, v.ID()))
	case artifact.Identifiable:
		id = string(v.ID())
	case artifact.ID:
		id = string(v)
	case string:
		id = v
	default:
		// FIXME don't panic here
		panic(fmt.Sprintf("Invalid ID type: %+v", v))
	}
	// NOTE: the spdx libraries prepend SPDXRef-
	return common.ElementID(id)
}

// packages populates all Package Information from the package Catalog (see https://spdx.github.io/spdx-spec/3-package-information/)
//
//nolint:funlen
func toPackages(catalog *pkg.Catalog, relationships []artifact.Relationship) (results []*spdx.Package) {
	for _, p := range catalog.Sorted() {
		// name should be guaranteed to be unique, but semantically useful and stable
		id := toSPDXID(p)

		// If the Concluded License is not the same as the Declared License, a written explanation should be provided
		// in the Comments on License field (section 3.16). With respect to NOASSERTION, a written explanation in
		// the Comments on License field (section 3.16) is preferred.
		license := License(p)
		checksums, filesAnalyzed := toPackageChecksums(p)

		results = append(results, &spdx.Package{
			// NOT PART OF SPEC
			// flag: does this "package" contain files that were in fact "unpackaged",
			// e.g. included directly in the Document without being in a Package?
			IsUnpackaged: false,

			// 3.1: Package Name
			// Cardinality: mandatory, one
			PackageName: p.Name,

			// 3.2: Package SPDX Identifier: "SPDXRef-[idstring]"
			// Cardinality: mandatory, one
			PackageSPDXIdentifier: id,

			// 3.3: Package Version
			// Cardinality: optional, one
			PackageVersion: p.Version,

			// 3.4: Package File Name
			// Cardinality: optional, one
			PackageFileName: "",

			// 3.5: Package Supplier: may have single result for either Person or Organization,
			//                        or NOASSERTION
			// Cardinality: optional, one

			// 3.6: Package Originator: may have single result for either Person or Organization,
			//                          or NOASSERTION
			// Cardinality: optional, one
			PackageSupplier: nil,

			PackageOriginator: toPackageOriginator(p),

			// 3.7: Package Download Location
			// Cardinality: mandatory, one
			// NONE if there is no download location whatsoever.
			// NOASSERTION if:
			//   (i) the SPDX file creator has attempted to but cannot reach a reasonable objective determination;
			//   (ii) the SPDX file creator has made no attempt to determine this field; or
			//   (iii) the SPDX file creator has intentionally provided no information (no meaning should be implied by doing so).
			PackageDownloadLocation: DownloadLocation(p),

			// 3.8: FilesAnalyzed
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

			// 3.9: Package Verification Code
			// Cardinality: optional, one if filesAnalyzed is true / omitted;
			//              zero (must be omitted) if filesAnalyzed is false
			PackageVerificationCode: nil,

			// 3.10: Package Checksum: may have keys for SHA1, SHA256 and/or MD5
			// Cardinality: optional, one or many

			// 3.10.1 Purpose: Provide an independently reproducible mechanism that permits unique identification of
			// a specific package that correlates to the data in this SPDX file. This identifier enables a recipient
			// to determine if any file in the original package has been changed. If the SPDX file is to be included
			// in a package, this value should not be calculated. The SHA-1 algorithm will be used to provide the
			// checksum by default.
			PackageChecksums: checksums,

			// 3.11: Package Home Page
			// Cardinality: optional, one
			PackageHomePage: Homepage(p),

			// 3.12: Source Information
			// Cardinality: optional, one
			PackageSourceInfo: SourceInfo(p),

			// 3.13: Concluded License: SPDX License Expression, "NONE" or "NOASSERTION"
			// Cardinality: mandatory, one
			// Purpose: Contain the license the SPDX file creator has concluded as governing the
			// package or alternative values, if the governing license cannot be determined.
			PackageLicenseConcluded: license,

			// 3.14: All Licenses Info from Files: SPDX License Expression, "NONE" or "NOASSERTION"
			// Cardinality: mandatory, one or many if filesAnalyzed is true / omitted;
			//              zero (must be omitted) if filesAnalyzed is false
			PackageLicenseInfoFromFiles: nil,

			// 3.15: Declared License: SPDX License Expression, "NONE" or "NOASSERTION"
			// Cardinality: mandatory, one
			// Purpose: List the licenses that have been declared by the authors of the package.
			// Any license information that does not originate from the package authors, e.g. license
			// information from a third party repository, should not be included in this field.
			PackageLicenseDeclared: license,

			// 3.16: Comments on License
			// Cardinality: optional, one
			PackageLicenseComments: "",

			// 3.17: Copyright Text: copyright notice(s) text, "NONE" or "NOASSERTION"
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

			// 3.18: Package Summary Description
			// Cardinality: optional, one
			PackageSummary: "",

			// 3.19: Package Detailed Description
			// Cardinality: optional, one
			PackageDescription: Description(p),

			// 3.20: Package Comment
			// Cardinality: optional, one
			PackageComment: "",

			// 3.21: Package External Reference
			// Cardinality: optional, one or many
			PackageExternalReferences: formatSPDXExternalRefs(p),

			// 3.22: Package External Reference Comment
			// Cardinality: conditional (optional, one) for each External Reference
			// contained within PackageExternalReference2_1 struct, if present

			// 3.23: Package Attribution Text
			// Cardinality: optional, one or many
			PackageAttributionTexts: nil,

			// Files contained in this Package
			Files: filesForPackage(id, relationships),
		})
	}
	return results
}

func toPackageOriginator(p pkg.Package) *common.Originator {
	kind, originator := Originator(p)
	if kind == "" || originator == "" {
		return nil
	}
	return &common.Originator{
		Originator:     originator,
		OriginatorType: kind,
	}
}

func toPackageChecksums(p pkg.Package) ([]common.Checksum, bool) {
	filesAnalyzed := false
	var checksums []common.Checksum
	switch meta := p.Metadata.(type) {
	// we generate digest for some Java packages
	// see page 33 of the spdx specification for 2.2
	// spdx.github.io/spdx-spec/package-information/#710-package-checksum-field
	case pkg.JavaMetadata:
		if len(meta.ArchiveDigests) > 0 {
			filesAnalyzed = true
			for _, digest := range meta.ArchiveDigests {
				checksums = append(checksums, common.Checksum{
					Algorithm: common.ChecksumAlgorithm(digest.Algorithm),
					Value:     digest.Value,
				})
			}
		}
	case pkg.GolangBinMetadata:
		algo, hexStr, err := util.HDigestToSHA(meta.H1Digest)
		if err != nil {
			log.Debugf("invalid h1digest: %s: %v", meta.H1Digest, err)
			break
		}
		algo = strings.ToUpper(algo)
		checksums = append(checksums, common.Checksum{
			Algorithm: common.ChecksumAlgorithm(algo),
			Value:     hexStr,
		})
	}
	return checksums, filesAnalyzed
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

		// FIXME: we are only currently including Package -> File CONTAINS relationships
		if _, ok := r.From.(pkg.Package); !ok {
			log.Debugf("skipping non-package relationship: %+v", r)
			continue
		}

		result = append(result, &spdx.Relationship{
			RefA: common.DocElementID{
				ElementRefID: toSPDXID(r.From),
			},
			Relationship: string(relationshipType),
			RefB: common.DocElementID{
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

		// TODO: add file classifications (?) and content as a snippet

		var comment string
		if coordinates.FileSystemID != "" {
			comment = fmt.Sprintf("layerID: %s", coordinates.FileSystemID)
		}

		results = append(results, &spdx.File{
			FileSPDXIdentifier: common.ElementID(coordinates.ID()),
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

func toFileChecksums(digests []file.Digest) (checksums []common.Checksum) {
	for _, digest := range digests {
		checksums = append(checksums, common.Checksum{
			Algorithm: toChecksumAlgorithm(digest.Algorithm),
			Value:     digest.Value,
		})
	}
	return checksums
}

func toChecksumAlgorithm(algorithm string) common.ChecksumAlgorithm {
	// basically, we need an uppercase version of our algorithm:
	// https://github.com/spdx/spdx-spec/blob/development/v2.2.2/schemas/spdx-schema.json#L165
	return common.ChecksumAlgorithm(strings.ToUpper(algorithm))
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
