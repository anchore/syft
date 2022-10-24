package spdx22json

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/common/spdxhelpers"
	"github.com/anchore/syft/syft/formats/common/util"
	"github.com/anchore/syft/syft/formats/spdx22json/model"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// toFormatModel creates and populates a new JSON document struct that follows the SPDX 2.2 spec from the given cataloging results.
func toFormatModel(s sbom.SBOM) *model.Document {
	name, namespace := spdxhelpers.DocumentNameAndNamespace(s.Source)

	relationships := s.RelationshipsSorted()

	return &model.Document{
		Element: model.Element{
			SPDXID: model.ElementID("DOCUMENT").String(),
			Name:   name,
		},
		SPDXVersion: model.Version,
		CreationInfo: model.CreationInfo{
			Created: time.Now().UTC(),
			Creators: []string{
				// note: key-value format derived from the JSON example document examples: https://github.com/spdx/spdx-spec/blob/v2.2/examples/SPDXJSONExample-v2.2.spdx.json
				"Organization: Anchore, Inc",
				"Tool: " + internal.ApplicationName + "-" + s.Descriptor.Version,
			},
			LicenseListVersion: spdxlicense.Version,
		},
		DataLicense:       "CC0-1.0",
		DocumentNamespace: namespace,
		Packages:          toPackages(s.Artifacts.PackageCatalog, relationships),
		Files:             toFiles(s),
		Relationships:     toRelationships(relationships),
	}
}

func toPackages(catalog *pkg.Catalog, relationships []artifact.Relationship) []model.Package {
	packages := make([]model.Package, 0)

	for _, p := range catalog.Sorted() {
		license := spdxhelpers.License(p)
		packageSpdxID := model.ElementID(p.ID()).String()
		checksums, filesAnalyzed := toPackageChecksums(p)

		// note: the license concluded and declared should be the same since we are collecting license information
		// from the project data itself (the installed package files).
		packages = append(packages, model.Package{
			Checksums:        checksums,
			Description:      spdxhelpers.Description(p),
			DownloadLocation: spdxhelpers.DownloadLocation(p),
			ExternalRefs:     spdxhelpers.ExternalRefs(p),
			FilesAnalyzed:    filesAnalyzed,
			HasFiles:         fileIDsForPackage(packageSpdxID, relationships),
			Homepage:         spdxhelpers.Homepage(p),
			// The Declared License is what the authors of a project believe govern the package
			LicenseDeclared: license,
			Originator:      spdxhelpers.Originator(p),
			SourceInfo:      spdxhelpers.SourceInfo(p),
			VersionInfo:     p.Version,
			Item: model.Item{
				// The Concluded License field is the license the SPDX file creator believes governs the package
				LicenseConcluded: license,
				Element: model.Element{
					SPDXID: packageSpdxID,
					Name:   p.Name,
				},
			},
		})
	}

	return packages
}

func toPackageChecksums(p pkg.Package) ([]model.Checksum, bool) {
	filesAnalyzed := false
	var checksums []model.Checksum
	switch meta := p.Metadata.(type) {
	// we generate digest for some Java packages
	// see page 33 of the spdx specification for 2.2
	// spdx.github.io/spdx-spec/package-information/#710-package-checksum-field
	case pkg.JavaMetadata:
		if len(meta.ArchiveDigests) > 0 {
			filesAnalyzed = true
			for _, digest := range meta.ArchiveDigests {
				checksums = append(checksums, model.Checksum{
					Algorithm:     strings.ToUpper(digest.Algorithm),
					ChecksumValue: digest.Value,
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
		checksums = append(checksums, model.Checksum{
			Algorithm:     strings.ToUpper(algo),
			ChecksumValue: hexStr,
		})
	}
	return checksums, filesAnalyzed
}

func fileIDsForPackage(packageSpdxID string, relationships []artifact.Relationship) (fileIDs []string) {
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

		from := model.ElementID(relationship.From.ID()).String()
		if from == packageSpdxID {
			to := model.ElementID(relationship.To.ID()).String()
			fileIDs = append(fileIDs, to)
		}
	}
	return fileIDs
}

func toFiles(s sbom.SBOM) []model.File {
	results := make([]model.File, 0)
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

		results = append(results, model.File{
			Item: model.Item{
				Element: model.Element{
					SPDXID:  model.ElementID(coordinates.ID()).String(),
					Comment: comment,
				},
				// required, no attempt made to determine license information
				LicenseConcluded: "NOASSERTION",
			},
			Checksums: toFileChecksums(digests),
			FileName:  coordinates.RealPath,
			FileTypes: toFileTypes(metadata),
		})
	}

	// sort by real path then virtual path to ensure the result is stable across multiple runs
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].FileName == results[j].FileName {
			return results[i].SPDXID < results[j].SPDXID
		}
		return results[i].FileName < results[j].FileName
	})
	return results
}

func toFileChecksums(digests []file.Digest) (checksums []model.Checksum) {
	for _, digest := range digests {
		checksums = append(checksums, model.Checksum{
			Algorithm:     toChecksumAlgorithm(digest.Algorithm),
			ChecksumValue: digest.Value,
		})
	}
	return checksums
}

func toChecksumAlgorithm(algorithm string) string {
	// basically, we need an uppercase version of our algorithm:
	// https://github.com/spdx/spdx-spec/blob/development/v2.2.2/schemas/spdx-schema.json#L165
	return strings.ToUpper(algorithm)
}

func toFileTypes(metadata *source.FileMetadata) (ty []string) {
	if metadata == nil {
		return nil
	}

	mimeTypePrefix := strings.Split(metadata.MIMEType, "/")[0]
	switch mimeTypePrefix {
	case "image":
		ty = append(ty, string(spdxhelpers.ImageFileType))
	case "video":
		ty = append(ty, string(spdxhelpers.VideoFileType))
	case "application":
		ty = append(ty, string(spdxhelpers.ApplicationFileType))
	case "text":
		ty = append(ty, string(spdxhelpers.TextFileType))
	case "audio":
		ty = append(ty, string(spdxhelpers.AudioFileType))
	}

	if internal.IsExecutable(metadata.MIMEType) {
		ty = append(ty, string(spdxhelpers.BinaryFileType))
	}

	if internal.IsArchive(metadata.MIMEType) {
		ty = append(ty, string(spdxhelpers.ArchiveFileType))
	}

	// TODO: add support for source, spdx, and documentation file types
	if len(ty) == 0 {
		ty = append(ty, string(spdxhelpers.OtherFileType))
	}

	return ty
}

func toRelationships(relationships []artifact.Relationship) (result []model.Relationship) {
	for _, r := range relationships {
		exists, relationshipType, comment := lookupRelationship(r.Type)

		if !exists {
			log.Warnf("unable to convert relationship from SPDX 2.2 JSON, dropping: %+v", r)
			continue
		}

		result = append(result, model.Relationship{
			SpdxElementID:      model.ElementID(r.From.ID()).String(),
			RelationshipType:   relationshipType,
			RelatedSpdxElement: model.ElementID(r.To.ID()).String(),
			Comment:            comment,
		})
	}
	return result
}

func lookupRelationship(ty artifact.RelationshipType) (bool, spdxhelpers.RelationshipType, string) {
	switch ty {
	case artifact.ContainsRelationship:
		return true, spdxhelpers.ContainsRelationship, ""
	case artifact.OwnershipByFileOverlapRelationship:
		return true, spdxhelpers.OtherRelationship, fmt.Sprintf("%s: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by", ty)
	}
	return false, "", ""
}
