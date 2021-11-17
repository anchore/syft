package spdx22json

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/artifact"

	"github.com/anchore/syft/syft/sbom"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/formats/common/spdxhelpers"
	"github.com/anchore/syft/internal/formats/spdx22json/model"
	"github.com/anchore/syft/internal/spdxlicense"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

// toFormatModel creates and populates a new JSON document struct that follows the SPDX 2.2 spec from the given cataloging results.
func toFormatModel(s sbom.SBOM) model.Document {
	name := documentName(s.Source)

	return model.Document{
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
				"Tool: " + internal.ApplicationName + "-" + version.FromBuild().Version,
			},
			LicenseListVersion: spdxlicense.Version,
		},
		DataLicense:       "CC0-1.0",
		DocumentNamespace: documentNamespace(name, s.Source),
		Packages:          toPackages(s.Artifacts.PackageCatalog, s.Relationships),
		Files:             toFiles(s),
		Relationships:     toRelationships(s.Relationships),
	}
}

func documentName(srcMetadata source.Metadata) string {
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		return cleanSPDXName(srcMetadata.ImageMetadata.UserInput)
	case source.DirectoryScheme:
		return cleanSPDXName(srcMetadata.Path)
	}

	// TODO: is this alright?
	return uuid.Must(uuid.NewRandom()).String()
}

func cleanSPDXName(name string) string {
	// remove # according to specification
	name = strings.ReplaceAll(name, "#", "-")

	// remove : for url construction
	name = strings.ReplaceAll(name, ":", "-")

	// clean relative pathing
	return path.Clean(name)
}

func documentNamespace(name string, srcMetadata source.Metadata) string {
	input := "unknown-source-type"
	switch srcMetadata.Scheme {
	case source.ImageScheme:
		input = "image"
	case source.DirectoryScheme:
		input = "dir"
	}

	uniqueID := uuid.Must(uuid.NewRandom())
	identifier := path.Join(input, uniqueID.String())
	if name != "." {
		identifier = path.Join(input, fmt.Sprintf("%s-%s", name, uniqueID.String()))
	}

	return path.Join(anchoreNamespace, identifier)
}

func toPackages(catalog *pkg.Catalog, relationships []artifact.Relationship) []model.Package {
	packages := make([]model.Package, 0)

	for _, p := range catalog.Sorted() {
		license := spdxhelpers.License(p)
		packageSpdxID := model.ElementID(p.ID()).String()

		// note: the license concluded and declared should be the same since we are collecting license information
		// from the project data itself (the installed package files).
		packages = append(packages, model.Package{
			Description:      spdxhelpers.Description(p),
			DownloadLocation: spdxhelpers.DownloadLocation(p),
			ExternalRefs:     spdxhelpers.ExternalRefs(p),
			FilesAnalyzed:    false,
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

func fileIDsForPackage(packageSpdxID string, relationships []artifact.Relationship) (fileIDs []string) {
	for _, relationship := range relationships {
		if relationship.Type != artifact.PackageOfRelationship {
			continue
		}

		if string(relationship.To.ID()) == packageSpdxID {
			fileIDs = append(fileIDs, string(relationship.From.ID()))
		}
	}
	return fileIDs
}

func toFiles(s sbom.SBOM) []model.File {
	results := make([]model.File, 0)
	artifacts := s.Artifacts

	for _, coordinates := range sbom.AllCoordinates(s) {
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
					SPDXID: string(coordinates.ID()),
					// TODO: this is encoding layer id... is there a better way?
					Name:    filepath.Base(coordinates.RealPath),
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
		return results[i].FileName < results[j].FileName
	})
	return results
}

func toFileChecksums(digests []file.Digest) (checksums []model.Checksum) {
	for _, digest := range digests {
		checksums = append(checksums, model.Checksum{
			Algorithm:     digest.Algorithm,
			ChecksumValue: digest.Value,
		})
	}
	return checksums
}

func toFileTypes(metadata *source.FileMetadata) (ty []string) {
	if metadata == nil {
		return nil
	}

	mimeTypePrefix := strings.Split(metadata.MIMEType, "/")[0]
	switch mimeTypePrefix {
	case "image":
		ty = append(ty, string(model.ImageFileType))
	case "video":
		ty = append(ty, string(model.VideoFileType))
	case "application":
		ty = append(ty, string(model.ApplicationFileType))
	case "text":
		ty = append(ty, string(model.TextFileType))
	case "audio":
		ty = append(ty, string(model.AudioFileType))
	}

	if internal.IsExecutable(metadata.MIMEType) {
		ty = append(ty, string(model.BinaryFileType))
	}

	if internal.IsArchive(metadata.MIMEType) {
		ty = append(ty, string(model.ArchiveFileType))
	}

	// TODO: source, spdx, and documentation
	if len(ty) == 0 {
		ty = append(ty, string(model.OtherFileType))
	}

	return ty
}

func toRelationships(relationships []artifact.Relationship) (result []model.Relationship) {
	for _, r := range relationships {
		exists, relationshipType, comment := lookupRelationship(r.Type)

		if !exists {
			// TODO: should we warn about lossyness here?
			continue
		}

		result = append(result, model.Relationship{
			SpdxElementID:      string(r.From.ID()),
			RelationshipType:   relationshipType,
			RelatedSpdxElement: string(r.To.ID()),
			Comment:            comment,
		})
	}
	return result
}

func lookupRelationship(ty artifact.RelationshipType) (bool, model.RelationshipType, string) {
	switch ty {
	case artifact.PackageOfRelationship:
		return true, model.PackageOfRelationship, ""
	case artifact.OwnershipByFileOverlapRelationship:
		return true, model.OtherRelationship, fmt.Sprintf("%s: indicates that the parent package claims ownership of a child package since the parent metadata indicates overlap with a location that a cataloger found the child package by", ty)
	}
	return false, "", ""
}
