package split

import (
	"slices"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// DropOption represents a drop option for filtering SBOM contents
type DropOption string

const (
	DropSource                      DropOption = "source"
	DropDescriptor                  DropOption = "descriptor"
	DropDistro                      DropOption = "distro"
	DropPkgLicenses                 DropOption = "pkg:licenses"
	DropPkgMetadataFiles            DropOption = "pkg:metadata.files"
	DropFileMetadata                DropOption = "file:metadata"
	DropFileDigests                 DropOption = "file:digests"
	DropFileExecutable              DropOption = "file:executable"
	DropFileUnknowns                DropOption = "file:unknowns"
	DropFileLicenses                DropOption = "file:licenses"
	DropFileContents                DropOption = "file:contents"
	DropLocationFSID                DropOption = "location:fsid"
	DropLocationNonPrimaryEvidence  DropOption = "location:non-primary-evidence"
	DropAll                         DropOption = "all"
)

// AllDropOptions returns all valid drop options (excluding "all")
func AllDropOptions() []DropOption {
	return []DropOption{
		DropSource,
		DropDescriptor,
		DropDistro,
		DropPkgLicenses,
		DropPkgMetadataFiles,
		DropFileMetadata,
		DropFileDigests,
		DropFileExecutable,
		DropFileUnknowns,
		DropFileLicenses,
		DropFileContents,
		DropLocationFSID,
		DropLocationNonPrimaryEvidence,
	}
}

// ParseDropOptions parses string values into DropOption values
func ParseDropOptions(values []string) []DropOption {
	var opts []DropOption
	for _, v := range values {
		opt := DropOption(strings.ToLower(strings.TrimSpace(v)))
		if opt == DropAll {
			return AllDropOptions()
		}
		opts = append(opts, opt)
	}
	return opts
}

// ApplyDropOptions applies the specified drop options to the SBOM
func ApplyDropOptions(s *sbom.SBOM, opts []DropOption) {
	if s == nil || len(opts) == 0 {
		return
	}

	for _, opt := range opts {
		switch opt {
		case DropSource:
			s.Source = source.Description{}
		case DropDescriptor:
			s.Descriptor = sbom.Descriptor{}
		case DropDistro:
			s.Artifacts.LinuxDistribution = nil
		case DropPkgLicenses:
			clearPackageLicenses(s)
		case DropPkgMetadataFiles:
			clearPackageMetadataFiles(s)
		case DropFileMetadata:
			s.Artifacts.FileMetadata = nil
		case DropFileDigests:
			s.Artifacts.FileDigests = nil
		case DropFileExecutable:
			s.Artifacts.Executables = nil
		case DropFileUnknowns:
			s.Artifacts.Unknowns = nil
		case DropFileLicenses:
			s.Artifacts.FileLicenses = nil
		case DropFileContents:
			s.Artifacts.FileContents = nil
		case DropLocationFSID:
			clearFileSystemIDs(s)
		case DropLocationNonPrimaryEvidence:
			clearNonPrimaryEvidenceLocations(s)
		}
	}
}

// GetJSONFieldsToRemove returns the JSON field names that should be completely removed from output
func GetJSONFieldsToRemove(opts []DropOption) []string {
	var fields []string
	for _, opt := range opts {
		switch opt {
		case DropSource:
			fields = append(fields, "source")
		case DropDescriptor:
			fields = append(fields, "descriptor")
		case DropDistro:
			fields = append(fields, "distro")
		}
	}
	return fields
}

// clearFileSystemIDs clears FileSystemID from all coordinates in file artifacts and relationships.
// Note: package locations are handled separately in the splitter when creating new packages.
func clearFileSystemIDs(s *sbom.SBOM) {
	// clear from file metadata
	if s.Artifacts.FileMetadata != nil {
		newMetadata := make(map[file.Coordinates]file.Metadata)
		for coord, meta := range s.Artifacts.FileMetadata {
			newCoord := file.Coordinates{RealPath: coord.RealPath}
			newMetadata[newCoord] = meta
		}
		s.Artifacts.FileMetadata = newMetadata
	}

	// clear from file digests
	if s.Artifacts.FileDigests != nil {
		newDigests := make(map[file.Coordinates][]file.Digest)
		for coord, digests := range s.Artifacts.FileDigests {
			newCoord := file.Coordinates{RealPath: coord.RealPath}
			newDigests[newCoord] = digests
		}
		s.Artifacts.FileDigests = newDigests
	}

	// clear from file contents
	if s.Artifacts.FileContents != nil {
		newContents := make(map[file.Coordinates]string)
		for coord, contents := range s.Artifacts.FileContents {
			newCoord := file.Coordinates{RealPath: coord.RealPath}
			newContents[newCoord] = contents
		}
		s.Artifacts.FileContents = newContents
	}

	// clear from file licenses
	if s.Artifacts.FileLicenses != nil {
		newLicenses := make(map[file.Coordinates][]file.License)
		for coord, licenses := range s.Artifacts.FileLicenses {
			newCoord := file.Coordinates{RealPath: coord.RealPath}
			newLicenses[newCoord] = licenses
		}
		s.Artifacts.FileLicenses = newLicenses
	}

	// clear from executables
	if s.Artifacts.Executables != nil {
		newExec := make(map[file.Coordinates]file.Executable)
		for coord, exec := range s.Artifacts.Executables {
			newCoord := file.Coordinates{RealPath: coord.RealPath}
			newExec[newCoord] = exec
		}
		s.Artifacts.Executables = newExec
	}

	// clear from unknowns
	if s.Artifacts.Unknowns != nil {
		newUnknowns := make(map[file.Coordinates][]string)
		for coord, unknowns := range s.Artifacts.Unknowns {
			newCoord := file.Coordinates{RealPath: coord.RealPath}
			newUnknowns[newCoord] = unknowns
		}
		s.Artifacts.Unknowns = newUnknowns
	}

	// clear from relationships that reference file coordinates
	newRelationships := make([]artifact.Relationship, 0, len(s.Relationships))
	for _, rel := range s.Relationships {
		newRel := rel

		if coord, ok := rel.From.(file.Coordinates); ok {
			newRel.From = file.Coordinates{RealPath: coord.RealPath}
		}
		if coord, ok := rel.To.(file.Coordinates); ok {
			newRel.To = file.Coordinates{RealPath: coord.RealPath}
		}

		newRelationships = append(newRelationships, newRel)
	}
	s.Relationships = newRelationships
}

// clearPackageLicenses removes licenses from all packages in the SBOM
func clearPackageLicenses(s *sbom.SBOM) {
	if s.Artifacts.Packages == nil {
		return
	}

	for p := range s.Artifacts.Packages.Enumerate() {
		p.Licenses = pkg.NewLicenseSet()
		s.Artifacts.Packages.Delete(p.ID())
		s.Artifacts.Packages.Add(p)
	}
}

// clearNonPrimaryEvidenceLocations removes locations that don't have "evidence": "primary" annotation
func clearNonPrimaryEvidenceLocations(s *sbom.SBOM) {
	if s.Artifacts.Packages == nil {
		return
	}

	for p := range s.Artifacts.Packages.Enumerate() {
		newLocations := file.NewLocationSet()
		for _, loc := range p.Locations.ToSlice() {
			if loc.Annotations != nil && loc.Annotations["evidence"] == "primary" {
				newLocations.Add(loc)
			}
		}
		p.Locations = newLocations
		s.Artifacts.Packages.Delete(p.ID())
		s.Artifacts.Packages.Add(p)
	}
}

// clearPackageMetadataFiles clears the Files field from any package metadata that implements FileOwner
func clearPackageMetadataFiles(s *sbom.SBOM) {
	if s.Artifacts.Packages == nil {
		return
	}

	for p := range s.Artifacts.Packages.Enumerate() {
		if p.Metadata == nil {
			continue
		}

		newMetadata := clearMetadataFiles(p.Metadata)
		if newMetadata != nil {
			p.Metadata = newMetadata
			s.Artifacts.Packages.Delete(p.ID())
			s.Artifacts.Packages.Add(p)
		}
	}
}

// clearMetadataFiles returns a copy of the metadata with Files field cleared if it implements FileOwner.
// Returns nil if the metadata type is not recognized as a FileOwner implementer.
func clearMetadataFiles(metadata any) any {
	switch m := metadata.(type) {
	case pkg.ApkDBEntry:
		m.Files = nil
		return m
	case pkg.RpmDBEntry:
		m.Files = nil
		return m
	case pkg.DpkgDBEntry:
		m.Files = nil
		return m
	case pkg.AlpmDBEntry:
		m.Files = nil
		return m
	case pkg.PortageEntry:
		m.Files = nil
		return m
	case pkg.NixStoreEntry:
		m.Files = nil
		return m
	case pkg.PythonPackage:
		m.Files = nil
		return m
	case pkg.CondaMetaPackage:
		m.Files = nil
		return m
	case pkg.BitnamiSBOMEntry:
		m.Files = nil
		return m
	case pkg.JavaVMInstallation:
		m.Files = nil
		return m
	}
	return nil
}

// ValidDropOption checks if a string is a valid drop option
func ValidDropOption(s string) bool {
	opt := DropOption(strings.ToLower(strings.TrimSpace(s)))
	if opt == DropAll {
		return true
	}
	return slices.Contains(AllDropOptions(), opt)
}

// HasDropLocationFSID checks if the drop options include location:fsid
func HasDropLocationFSID(opts []DropOption) bool {
	return slices.Contains(opts, DropLocationFSID)
}

// HasDropLocationNonPrimaryEvidence checks if the drop options include location:non-primary-evidence
func HasDropLocationNonPrimaryEvidence(opts []DropOption) bool {
	return slices.Contains(opts, DropLocationNonPrimaryEvidence)
}
