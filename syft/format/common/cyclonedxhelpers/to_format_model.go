package cyclonedxhelpers

import (
	"fmt"
	"slices"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	stfile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/cyclonedxutil/helpers"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var cycloneDXValidHash = map[string]cyclonedx.HashAlgorithm{
	"sha1":       cyclonedx.HashAlgoSHA1,
	"md5":        cyclonedx.HashAlgoMD5,
	"sha256":     cyclonedx.HashAlgoSHA256,
	"sha384":     cyclonedx.HashAlgoSHA384,
	"sha512":     cyclonedx.HashAlgoSHA512,
	"blake2b256": cyclonedx.HashAlgoBlake2b_256,
	"blake2b384": cyclonedx.HashAlgoBlake2b_384,
	"blake2b512": cyclonedx.HashAlgoBlake2b_512,
	"blake3":     cyclonedx.HashAlgoBlake3,
}

func ToFormatModel(s sbom.SBOM) *cyclonedx.BOM {
	cdxBOM := cyclonedx.NewBOM()

	// NOTE(jonasagx): cycloneDX requires URN uuids (URN returns the RFC 2141 URN form of uuid):
	// https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3-strict.schema.json#L36
	// "pattern": "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	cdxBOM.SerialNumber = uuid.New().URN()
	cdxBOM.Metadata = toBomDescriptor(s.Descriptor.Name, s.Descriptor.Version, s.Source)

	coordinates, locationSorter := getCoordinates(s)

	// Packages
	packages := s.Artifacts.Packages.Sorted()
	components := make([]cyclonedx.Component, len(packages))
	for i, p := range packages {
		components[i] = helpers.EncodeComponent(p, locationSorter)
	}
	components = append(components, toOSComponent(s.Artifacts.LinuxDistribution)...)

	artifacts := s.Artifacts

	for _, coordinate := range coordinates {
		var metadata *file.Metadata
		// File Info
		fileMetadata, exists := artifacts.FileMetadata[coordinate]
		// no file metadata then don't include in SBOM
		// the syft config allows for sometimes only capturing files owned by packages
		// so there can be a map miss here where we have less metadata than all coordinates
		if !exists {
			continue
		}
		if fileMetadata.Type == stfile.TypeDirectory ||
			fileMetadata.Type == stfile.TypeSocket ||
			fileMetadata.Type == stfile.TypeSymLink {
			// skip dir, symlinks and sockets for the final bom
			continue
		}
		metadata = &fileMetadata

		// Digests
		var digests []file.Digest
		if digestsForLocation, exists := artifacts.FileDigests[coordinate]; exists {
			digests = digestsForLocation
		}

		cdxHashes := digestsToHashes(digests)
		components = append(components, cyclonedx.Component{
			BOMRef: string(coordinate.ID()),
			Type:   cyclonedx.ComponentTypeFile,
			Name:   metadata.Path,
			Hashes: &cdxHashes,
		})
	}
	cdxBOM.Components = &components

	dependencies := toDependencies(s.Relationships)
	if len(dependencies) > 0 {
		cdxBOM.Dependencies = &dependencies
	}

	return cdxBOM
}

func getCoordinates(s sbom.SBOM) ([]file.Coordinates, func(a, b file.Location) int) {
	var layers []string
	if m, ok := s.Source.Metadata.(source.ImageMetadata); ok {
		for _, l := range m.Layers {
			layers = append(layers, l.Digest)
		}
	}

	coordSorter := file.CoordinatesSorter(layers)
	coordinates := s.AllCoordinates()

	slices.SortFunc(coordinates, coordSorter)
	return coordinates, file.LocationSorter(layers)
}

func digestsToHashes(digests []file.Digest) []cyclonedx.Hash {
	var hashes []cyclonedx.Hash
	for _, digest := range digests {
		lookup := strings.ToLower(digest.Algorithm)
		cdxAlgo, exists := cycloneDXValidHash[lookup]
		if !exists {
			continue
		}
		hashes = append(hashes, cyclonedx.Hash{
			Algorithm: cdxAlgo,
			Value:     digest.Value,
		})
	}
	return hashes
}

func toOSComponent(distro *linux.Release) []cyclonedx.Component {
	if distro == nil {
		return []cyclonedx.Component{}
	}
	eRefs := &[]cyclonedx.ExternalReference{}
	if distro.BugReportURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:  distro.BugReportURL,
			Type: cyclonedx.ERTypeIssueTracker,
		})
	}
	if distro.HomeURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:  distro.HomeURL,
			Type: cyclonedx.ERTypeWebsite,
		})
	}
	if distro.SupportURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:     distro.SupportURL,
			Type:    cyclonedx.ERTypeOther,
			Comment: "support",
		})
	}
	if distro.PrivacyPolicyURL != "" {
		*eRefs = append(*eRefs, cyclonedx.ExternalReference{
			URL:     distro.PrivacyPolicyURL,
			Type:    cyclonedx.ERTypeOther,
			Comment: "privacyPolicy",
		})
	}
	if len(*eRefs) == 0 {
		eRefs = nil
	}
	props := helpers.EncodeProperties(distro, "syft:distro")
	var properties *[]cyclonedx.Property
	if len(props) > 0 {
		properties = &props
	}
	return []cyclonedx.Component{
		{
			BOMRef: toOSBomRef(distro.ID, distro.VersionID),
			Type:   cyclonedx.ComponentTypeOS,
			// is it idiomatic to be using SWID here for specific name and version information?
			SWID: &cyclonedx.SWID{
				TagID:   distro.ID,
				Name:    distro.ID,
				Version: distro.VersionID,
			},
			Description: distro.PrettyName,
			Name:        distro.ID,
			Version:     distro.VersionID,
			// should we add a PURL?
			CPE:                formatCPE(distro.CPEName),
			ExternalReferences: eRefs,
			Properties:         properties,
		},
	}
}

func toOSBomRef(name string, version string) string {
	if name == "" {
		return "os:unknown"
	}
	if version == "" {
		return fmt.Sprintf("os:%s", name)
	}
	return fmt.Sprintf("os:%s@%s", name, version)
}

func formatCPE(cpeString string) string {
	c, err := cpe.NewAttributes(cpeString)
	if err != nil {
		log.Debugf("skipping invalid CPE: %s", cpeString)
		return ""
	}
	return c.String()
}

// NewBomDescriptor returns a new BomDescriptor tailored for the current time and "syft" tool details.
func toBomDescriptor(name, version string, srcMetadata source.Description) *cyclonedx.Metadata {
	return &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Type:    cyclonedx.ComponentTypeApplication,
					Author:  "anchore",
					Name:    name,
					Version: version,
				},
			},
		},
		Properties: toBomProperties(srcMetadata),
		Component:  toBomDescriptorComponent(srcMetadata),
	}
}

// used to indicate that a relationship listed under the syft artifact package can be represented as a cyclonedx dependency.
// NOTE: CycloneDX provides the ability to describe components and their dependency on other components.
// The dependency graph is capable of representing both direct and transitive relationships.
// If a relationship is either direct or transitive it can be included in this function.
// An example of a relationship to not include would be: OwnershipByFileOverlapRelationship.
func isExpressiblePackageRelationship(ty artifact.RelationshipType) bool {
	switch ty {
	case artifact.DependencyOfRelationship:
		return true
	default:
		return false
	}
}

func toDependencies(relationships []artifact.Relationship) []cyclonedx.Dependency {
	dependencies := map[string]*cyclonedx.Dependency{}
	for _, r := range relationships {
		exists := isExpressiblePackageRelationship(r.Type)
		if !exists {
			log.Debugf("unable to convert relationship type to CycloneDX JSON, dropping: %#v", r)
			continue
		}

		// we only capture package-to-package relationships for now
		fromPkg, ok := r.From.(pkg.Package)
		if !ok {
			log.Tracef("unable to convert relationship fromPkg to CycloneDX JSON, dropping: %#v", r)
			continue
		}

		toPkg, ok := r.To.(pkg.Package)
		if !ok {
			log.Tracef("unable to convert relationship toPkg to CycloneDX JSON, dropping: %#v", r)
			continue
		}

		toRef := helpers.DeriveBomRef(toPkg)
		dep := dependencies[toRef]
		if dep == nil {
			dep = &cyclonedx.Dependency{
				Ref:          toRef,
				Dependencies: &[]string{},
			}
			dependencies[toRef] = dep
		}

		fromRef := helpers.DeriveBomRef(fromPkg)
		if !slices.Contains(*dep.Dependencies, fromRef) {
			*dep.Dependencies = append(*dep.Dependencies, fromRef)
		}
	}

	result := make([]cyclonedx.Dependency, 0, len(dependencies))
	for _, dep := range dependencies {
		slices.Sort(*dep.Dependencies)
		result = append(result, *dep)
	}

	slices.SortFunc(result, func(a, b cyclonedx.Dependency) int {
		return strings.Compare(a.Ref, b.Ref)
	})

	return result
}

func toBomProperties(srcMetadata source.Description) *[]cyclonedx.Property {
	metadata, ok := srcMetadata.Metadata.(source.ImageMetadata)
	if ok {
		props := helpers.EncodeProperties(metadata.Labels, "syft:image:labels")
		// return nil if props is nil to avoid creating a pointer to a nil slice,
		// which results in a null JSON value that does not comply with the CycloneDX schema.
		// https://github.com/anchore/grype/issues/1759
		if props == nil {
			return nil
		}
		return &props
	}
	return nil
}

func toBomDescriptorComponent(srcMetadata source.Description) *cyclonedx.Component {
	name := srcMetadata.Name
	version := srcMetadata.Version
	switch metadata := srcMetadata.Metadata.(type) {
	case source.ImageMetadata:
		if name == "" {
			name = metadata.UserInput
		}
		if version == "" {
			version = metadata.ManifestDigest
		}
		bomRef, err := artifact.IDByHash(metadata.ID)
		if err != nil {
			log.Debugf("unable to get fingerprint of source image metadata=%s: %+v", metadata.ID, err)
		}
		return &cyclonedx.Component{
			BOMRef:  string(bomRef),
			Type:    cyclonedx.ComponentTypeContainer,
			Name:    name,
			Version: version,
		}
	case source.DirectoryMetadata:
		if name == "" {
			name = metadata.Path
		}
		bomRef, err := artifact.IDByHash(metadata.Path)
		if err != nil {
			log.Debugf("unable to get fingerprint of source directory metadata path=%s: %+v", metadata.Path, err)
		}
		return &cyclonedx.Component{
			BOMRef: string(bomRef),
			// TODO: this is lossy... we can't know if this is a file or a directory
			Type:    cyclonedx.ComponentTypeFile,
			Name:    name,
			Version: version,
		}
	case source.FileMetadata:
		if name == "" {
			name = metadata.Path
		}
		bomRef, err := artifact.IDByHash(metadata.Path)
		if err != nil {
			log.Debugf("unable to get fingerprint of source file metadata path=%s: %+v", metadata.Path, err)
		}
		return &cyclonedx.Component{
			BOMRef: string(bomRef),
			// TODO: this is lossy... we can't know if this is a file or a directory
			Type:    cyclonedx.ComponentTypeFile,
			Name:    name,
			Version: version,
		}
	}

	return nil
}
