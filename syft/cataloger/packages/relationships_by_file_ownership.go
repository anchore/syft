package packages

import (
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/scylladb/go-set/strset"
)

var globsForbiddenFromBeingOwned = []string{
	// any OS DBs should automatically be ignored to prevent cyclic issues (e.g. the "rpm" RPM owns the path to the
	// RPM DB, so if not ignored that package would own all other packages on the system).
	pkg.ApkDBGlob,
	pkg.DpkgDBGlob,
	pkg.RpmDBGlob,
	// DEB packages share common copyright info between, this does not mean that sharing these paths implies ownership.
	"/usr/share/doc/**/copyright",
}

type ownershipByFilesMetadata struct {
	Files []string `json:"files"`
}

func createFileOwnershipRelationships(p pkg.Package, resolver file.PathResolver) ([]artifact.Relationship, error) {
	fileOwner, ok := p.Metadata.(pkg.FileOwner)
	if !ok {
		return nil, nil
	}

	var relationships []artifact.Relationship

	for _, path := range fileOwner.OwnedFiles() {
		locations, err := resolver.FilesByPath(path)
		if err != nil {
			return nil, fmt.Errorf("unable to find path for path=%q: %w", path, err)
		}

		if len(locations) == 0 {
			// ideally we want to warn users about missing files from a package, however, it is very common for
			// container image authors to delete files that are not needed in order to keep image sizes small. Adding
			// a warning here would be needlessly noisy (even for popular base images).
			continue
		}

		for _, l := range locations {
			relationships = append(relationships, artifact.Relationship{
				From: p,
				To:   l.Coordinates,
				Type: artifact.ContainsRelationship,
			})
		}
	}

	return relationships, nil
}

// findOwnershipByFileOverlapRelationship creates a package-to-package relationship based on discovering which packages have
// evidence locations that overlap with ownership claim from another package's package manager metadata.
func findOwnershipByFileOverlapRelationship(catalog pkg.Collection) []artifact.Relationship {
	var relationships = findFilesWithDisputedOwnership(catalog)

	var edges []artifact.Relationship
	for parentID, children := range relationships {
		for childID, files := range children {
			edges = append(edges, artifact.Relationship{
				From: catalog.Package(parentID),
				To:   catalog.Package(childID),
				Type: artifact.OwnershipByFileOverlapRelationship,
				Data: ownershipByFilesMetadata{
					Files: files.List(),
				},
			})
		}
	}

	return edges
}

// findFilesWithDisputedOwnership find overlaps in file ownership with a file that defines another package. Specifically, a .Location.Path of
// a package is found to be owned by another (from the owner's .Metadata.Files[]).
func findFilesWithDisputedOwnership(catalog pkg.Collection) map[artifact.ID]map[artifact.ID]*strset.Set {
	var relationships = make(map[artifact.ID]map[artifact.ID]*strset.Set)

	if catalog == nil {
		return relationships
	}

	for _, candidateOwnerPkg := range catalog.Sorted() {
		id := candidateOwnerPkg.ID()
		if candidateOwnerPkg.Metadata == nil {
			continue
		}

		// check to see if this is a file owner
		pkgFileOwner, ok := candidateOwnerPkg.Metadata.(pkg.FileOwner)
		if !ok {
			continue
		}
		for _, ownedFilePath := range pkgFileOwner.OwnedFiles() {
			if matchesAny(ownedFilePath, globsForbiddenFromBeingOwned) {
				// we skip over known exceptions to file ownership, such as the RPM package owning
				// the RPM DB path, otherwise the RPM package would "own" all RPMs, which is not intended
				continue
			}

			// look for package(s) in the catalog that may be owned by this package and mark the relationship
			for _, subPackage := range catalog.PackagesByPath(ownedFilePath) {
				subID := subPackage.ID()
				if subID == id {
					continue
				}
				if _, exists := relationships[id]; !exists {
					relationships[id] = make(map[artifact.ID]*strset.Set)
				}

				if _, exists := relationships[id][subID]; !exists {
					relationships[id][subID] = strset.New()
				}
				relationships[id][subID].Add(ownedFilePath)
			}
		}
	}

	return relationships
}

func matchesAny(s string, globs []string) bool {
	for _, g := range globs {
		matches, err := doublestar.Match(g, s)
		if err != nil {
			log.Errorf("failed to match glob=%q : %+v", g, err)
		}
		if matches {
			return true
		}
	}
	return false
}
