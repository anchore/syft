package pkg

import "github.com/scylladb/go-set/strset"

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
				Type:   OwnershipByFilesRelationship,
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

	for _, candidateOwnerPkg := range catalog.Sorted() {
		if candidateOwnerPkg.Metadata == nil {
			continue
		}

		// check to see if this is a file owner
		pkgFileOwner, ok := candidateOwnerPkg.Metadata.(fileOwner)
		if !ok {
			continue
		}
		for _, ownedFilePath := range pkgFileOwner.ownedFiles() {
			if matchesAny(ownedFilePath, forbiddenOwnershipGlobs) {
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
