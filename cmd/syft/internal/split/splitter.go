package split

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// allowedRelationshipTypes are the only relationship types allowed in split output
var allowedRelationshipTypes = []artifact.RelationshipType{
	artifact.OwnershipByFileOverlapRelationship,
	artifact.EvidentByRelationship,
}

// Result represents the result of splitting an SBOM for a single target package
type Result struct {
	TargetPackage pkg.Package
	SBOM          sbom.SBOM
}

// Split splits the source SBOM into separate SBOMs, one for each target package.
// Each output SBOM contains the target package, its connected packages (via ownership-by-file-overlap
// and evident-by relationships), and all related files.
func Split(source sbom.SBOM, targetPackages []pkg.Package, dropLocationFSID, dropNonPrimaryEvidence bool) []Result {
	if len(targetPackages) == 0 {
		return nil
	}

	relIndex := newRelationshipIndex(source.Relationships...)
	results := make([]Result, 0, len(targetPackages))

	for _, target := range targetPackages {
		result := splitForPackage(source, target, relIndex, dropLocationFSID, dropNonPrimaryEvidence)
		results = append(results, result)
	}

	return results
}

// splitForPackage creates a new SBOM containing only the target package and its related artifacts
func splitForPackage(source sbom.SBOM, target pkg.Package, relIndex *relationshipIndex, dropLocationFSID, dropNonPrimaryEvidence bool) Result {
	// find all connected packages via BFS
	connectedPkgs := findConnectedPackages(source, target, relIndex)

	// collect all kept package IDs for relationship filtering
	keptPkgIDs := make(map[artifact.ID]bool)
	for _, p := range connectedPkgs {
		keptPkgIDs[p.ID()] = true
	}

	// find related file coordinates from relationships and package locations
	keptCoords := collectFileCoordinates(connectedPkgs, relIndex, dropLocationFSID, dropNonPrimaryEvidence)

	// build filtered SBOM
	filteredSBOM := buildFilteredSBOM(source, connectedPkgs, keptPkgIDs, keptCoords, relIndex, dropLocationFSID, dropNonPrimaryEvidence)

	return Result{
		TargetPackage: target,
		SBOM:          filteredSBOM,
	}
}

// findConnectedPackages uses BFS to find all packages connected to the target via traversal relationships
func findConnectedPackages(source sbom.SBOM, target pkg.Package, relIndex *relationshipIndex) []pkg.Package {
	visited := make(map[artifact.ID]bool)
	var result []pkg.Package

	queue := []pkg.Package{target}
	visited[target.ID()] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		// find connected packages through relationships (both directions)
		for _, rel := range relIndex.from(current, allowedRelationshipTypes...) {
			toID := rel.To.ID()
			if visited[toID] {
				continue
			}
			// check if the target is a package in the source collection
			if p := source.Artifacts.Packages.Package(toID); p != nil {
				visited[toID] = true
				queue = append(queue, *p)
			}
		}

		for _, rel := range relIndex.to(current, allowedRelationshipTypes...) {
			fromID := rel.From.ID()
			if visited[fromID] {
				continue
			}
			// check if the source is a package in the source collection
			if p := source.Artifacts.Packages.Package(fromID); p != nil {
				visited[fromID] = true
				queue = append(queue, *p)
			}
		}
	}

	return result
}

// collectFileCoordinates gathers all file coordinates related to the kept packages
func collectFileCoordinates(packages []pkg.Package, relIndex *relationshipIndex, dropLocationFSID, dropNonPrimaryEvidence bool) map[file.Coordinates]bool {
	coords := make(map[file.Coordinates]bool)

	for _, p := range packages {
		// collect coordinates from package locations
		for _, loc := range p.Locations.ToSlice() {
			// skip non-primary evidence locations if requested
			if dropNonPrimaryEvidence {
				if loc.Annotations == nil || loc.Annotations["evidence"] != "primary" {
					continue
				}
			}
			coord := loc.Coordinates
			if dropLocationFSID {
				coord = file.Coordinates{RealPath: coord.RealPath}
			}
			coords[coord] = true
		}

		// collect coordinates from allowed relationship types only
		for _, c := range relIndex.coordinates(p, allowedRelationshipTypes...) {
			coord := c
			if dropLocationFSID {
				coord = file.Coordinates{RealPath: c.RealPath}
			}
			coords[coord] = true
		}
	}

	return coords
}

// buildFilteredSBOM creates a new SBOM with only the kept packages, files, and relationships
func buildFilteredSBOM(source sbom.SBOM, packages []pkg.Package, keptPkgIDs map[artifact.ID]bool, keptCoords map[file.Coordinates]bool, relIndex *relationshipIndex, dropLocationFSID, dropNonPrimaryEvidence bool) sbom.SBOM {
	// create new package collection
	newPkgCollection := pkg.NewCollection()
	for _, p := range packages {
		// filter non-primary evidence locations if requested
		if dropNonPrimaryEvidence {
			p = filterPackageNonPrimaryLocations(p)
		}
		// if dropLocationFSID is enabled, we need to clear FileSystemID from package locations
		if dropLocationFSID {
			p = clearPackageFileSystemIDs(p)
		}
		newPkgCollection.Add(p)
	}

	// filter file artifacts
	filteredSBOM := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          newPkgCollection,
			FileMetadata:      filterFileMap(source.Artifacts.FileMetadata, keptCoords, dropLocationFSID),
			FileDigests:       filterFileMap(source.Artifacts.FileDigests, keptCoords, dropLocationFSID),
			FileContents:      filterFileMap(source.Artifacts.FileContents, keptCoords, dropLocationFSID),
			FileLicenses:      filterFileMap(source.Artifacts.FileLicenses, keptCoords, dropLocationFSID),
			Executables:       filterFileMap(source.Artifacts.Executables, keptCoords, dropLocationFSID),
			Unknowns:          filterFileMap(source.Artifacts.Unknowns, keptCoords, dropLocationFSID),
			LinuxDistribution: source.Artifacts.LinuxDistribution,
		},
		Relationships: filterRelationships(relIndex.all(), keptPkgIDs, keptCoords, dropLocationFSID),
		Source:        source.Source,
		Descriptor:    source.Descriptor,
	}

	return filteredSBOM
}

// filterPackageNonPrimaryLocations creates a copy of the package with only primary evidence locations
func filterPackageNonPrimaryLocations(p pkg.Package) pkg.Package {
	newLocations := file.NewLocationSet()
	for _, loc := range p.Locations.ToSlice() {
		if loc.Annotations != nil && loc.Annotations["evidence"] == "primary" {
			newLocations.Add(loc)
		}
	}
	p.Locations = newLocations
	return p
}

// filterFileMap filters a map of file.Coordinates to only include kept coordinates
func filterFileMap[T any](m map[file.Coordinates]T, keptCoords map[file.Coordinates]bool, dropLocationFSID bool) map[file.Coordinates]T {
	if m == nil {
		return nil
	}

	result := make(map[file.Coordinates]T)
	for coord, value := range m {
		checkCoord := coord
		if dropLocationFSID {
			checkCoord = file.Coordinates{RealPath: coord.RealPath}
		}
		if keptCoords[checkCoord] {
			outputCoord := coord
			if dropLocationFSID {
				outputCoord = file.Coordinates{RealPath: coord.RealPath}
			}
			result[outputCoord] = value
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// filterRelationships filters relationships to only include allowed types referencing kept artifacts
func filterRelationships(relationships []artifact.Relationship, keptPkgIDs map[artifact.ID]bool, keptCoords map[file.Coordinates]bool, dropLocationFSID bool) []artifact.Relationship {
	var result []artifact.Relationship

	for _, rel := range relationships {
		// only keep allowed relationship types
		if !isAllowedRelationshipType(rel.Type) {
			continue
		}

		// check if both ends of the relationship reference kept artifacts
		fromKept := isArtifactKept(rel.From, keptPkgIDs, keptCoords, dropLocationFSID)
		toKept := isArtifactKept(rel.To, keptPkgIDs, keptCoords, dropLocationFSID)

		if fromKept && toKept {
			newRel := rel
			if dropLocationFSID {
				if coord, ok := rel.From.(file.Coordinates); ok {
					newRel.From = file.Coordinates{RealPath: coord.RealPath}
				}
				if coord, ok := rel.To.(file.Coordinates); ok {
					newRel.To = file.Coordinates{RealPath: coord.RealPath}
				}
			}
			result = append(result, newRel)
		}
	}

	return result
}

// isAllowedRelationshipType checks if a relationship type is in the allowed list
func isAllowedRelationshipType(t artifact.RelationshipType) bool {
	for _, allowed := range allowedRelationshipTypes {
		if t == allowed {
			return true
		}
	}
	return false
}

// isArtifactKept checks if an artifact (package or file) is in the kept set
func isArtifactKept(a artifact.Identifiable, keptPkgIDs map[artifact.ID]bool, keptCoords map[file.Coordinates]bool, dropLocationFSID bool) bool {
	if a == nil {
		return false
	}

	// check if it's a file coordinate
	if coord, ok := a.(file.Coordinates); ok {
		checkCoord := coord
		if dropLocationFSID {
			checkCoord = file.Coordinates{RealPath: coord.RealPath}
		}
		return keptCoords[checkCoord]
	}

	// otherwise check package ID
	return keptPkgIDs[a.ID()]
}

// clearPackageFileSystemIDs creates a copy of the package with FileSystemID cleared from all locations
func clearPackageFileSystemIDs(p pkg.Package) pkg.Package {
	newLocations := file.NewLocationSet()
	for _, loc := range p.Locations.ToSlice() {
		newLoc := file.Location{
			LocationData: file.LocationData{
				Coordinates: file.Coordinates{
					RealPath: loc.RealPath,
					// FileSystemID intentionally left empty
				},
				AccessPath: loc.AccessPath,
			},
			LocationMetadata: loc.LocationMetadata,
		}
		newLocations.Add(newLoc)
	}
	p.Locations = newLocations

	// also clear from license locations
	newLicenses := pkg.NewLicenseSet()
	for _, lic := range p.Licenses.ToSlice() {
		newLicLocs := file.NewLocationSet()
		for _, loc := range lic.Locations.ToSlice() {
			newLoc := file.Location{
				LocationData: file.LocationData{
					Coordinates: file.Coordinates{
						RealPath: loc.RealPath,
					},
					AccessPath: loc.AccessPath,
				},
				LocationMetadata: loc.LocationMetadata,
			}
			newLicLocs.Add(newLoc)
		}
		lic.Locations = newLicLocs
		newLicenses.Add(lic)
	}
	p.Licenses = newLicenses

	return p
}
