package pkg

import (
	"github.com/anchore/syft/internal/log"
	"github.com/bmatcuk/doublestar/v2"
	"github.com/scylladb/go-set/strset"
)

var globsForbiddenFromBeingOwned = []string{
	// any OS DBs should automatically be ignored to prevent cyclic issues (e.g. the "rpm" RPM owns the path to the
	// RPM DB, so if not ignored that package would own all other packages on the system).
	ApkDbGlob,
	DpkgDbGlob,
	RpmDbGlob,
	// DEB packages share common copyright info between, this does not mean that sharing these paths implies ownership.
	"/usr/share/doc/**/copyright",
}

type ownershipByFilesMetadata struct {
	Files []string `json:"files"`
}

func ownershipByFilesRelationships(catalog *Catalog) []Relationship {
	var relationships = findOwnershipByFilesRelationships(catalog)

	var edges []Relationship
	for parent, children := range relationships {
		for child, files := range children {
			edges = append(edges, Relationship{
				Parent: parent,
				Child:  child,
				Type:   OwnershipByFileOverlapRelationship,
				Metadata: ownershipByFilesMetadata{
					Files: files.List(),
				},
			})
		}
	}

	return edges
}

// findOwnershipByFilesRelationships find overlaps in file ownership with a file that defines another package. Specifically, a .Location.Path of
// a package is found to be owned by another (from the owner's .Metadata.Files[]).
func findOwnershipByFilesRelationships(catalog *Catalog) map[ID]map[ID]*strset.Set {
	var relationships = make(map[ID]map[ID]*strset.Set)

	if catalog == nil {
		return relationships
	}

	for _, candidateOwnerPkg := range catalog.Sorted() {
		if candidateOwnerPkg.Metadata == nil {
			continue
		}

		// check to see if this is a file owner
		pkgFileOwner, ok := candidateOwnerPkg.Metadata.(FileOwner)
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
				if subPackage.ID == candidateOwnerPkg.ID {
					continue
				}
				if _, exists := relationships[candidateOwnerPkg.ID]; !exists {
					relationships[candidateOwnerPkg.ID] = make(map[ID]*strset.Set)
				}

				if _, exists := relationships[candidateOwnerPkg.ID][subPackage.ID]; !exists {
					relationships[candidateOwnerPkg.ID][subPackage.ID] = strset.New()
				}
				relationships[candidateOwnerPkg.ID][subPackage.ID].Add(ownedFilePath)
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
