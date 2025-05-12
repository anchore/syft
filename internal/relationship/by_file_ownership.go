package relationship

import (
	"sort"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// altRpmDBGlob allows db matches against new locations introduced in fedora:{36,37}
// See https://github.com/anchore/syft/issues/1077 for larger context
const altRpmDBGlob = "**/rpm/{Packages,Packages.db,rpmdb.sqlite}"

var globsForbiddenFromBeingOwned = []string{
	// any OS DBs should automatically be ignored to prevent cyclic issues (e.g. the "rpm" RPM owns the path to the
	// RPM DB, so if not ignored that package would own all other packages on the system).
	pkg.ApkDBGlob,
	pkg.DpkgDBGlob,
	pkg.RpmDBGlob,
	altRpmDBGlob,
	// DEB packages share common copyright info between, this does not mean that sharing these paths implies ownership.
	"/usr/share/doc/**/copyright",
}

type ownershipByFilesMetadata struct {
	Files []string `json:"files"`
}

func ByFileOwnershipOverlapWorker(resolver file.Resolver, accessor sbomsync.Accessor) {
	var relationships []artifact.Relationship

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		relationships = byFileOwnershipOverlap(resolver, s.Artifacts.Packages)
	})

	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		s.Relationships = append(s.Relationships, relationships...)
	})
}

// byFileOwnershipOverlap creates a package-to-package relationship based on discovering which packages have
// evidence locations that overlap with ownership claim from another package's package manager metadata.
func byFileOwnershipOverlap(resolver file.Resolver, catalog *pkg.Collection) []artifact.Relationship {
	var relationships = findOwnershipByFilesRelationships(resolver, catalog)

	var edges []artifact.Relationship
	for parentID, children := range relationships {
		for childID, files := range children {
			fs := files.List()
			sort.Strings(fs)

			parent := catalog.Package(parentID) // TODO: this is potentially expensive
			child := catalog.Package(childID)   // TODO: this is potentially expensive

			if parent == nil {
				log.Tracef("parent package not found: %v", parentID)
				continue
			}

			if child == nil {
				log.Tracef("child package not found: %v", childID)
				continue
			}

			edges = append(edges, artifact.Relationship{
				From: *parent,
				To:   *child,
				Type: artifact.OwnershipByFileOverlapRelationship,
				Data: ownershipByFilesMetadata{
					Files: fs,
				},
			})
		}
	}

	return edges
}

// findOwnershipByFilesRelationships find overlaps in file ownership with a file that defines another package. Specifically, a .Location.Path of
// a package is found to be owned by another (from the owner's .Metadata.Files[]).
func findOwnershipByFilesRelationships(resolver file.Resolver, catalog *pkg.Collection) map[artifact.ID]map[artifact.ID]*strset.Set { //nolint:gocognit
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
			// find the first path that results in a hit
			for _, ownedPath := range allPaths(ownedFilePath, resolver) {
				if matchesAny(ownedPath, globsForbiddenFromBeingOwned) {
					// we skip over known exceptions to file ownership, such as the RPM package owning
					// the RPM DB path, otherwise the RPM package would "own" all RPMs, which is not intended
					continue
				}

				// look for package(s) in the catalog that may be owned by this package and mark the relationship
				for _, subPackage := range catalog.PackagesByPath(ownedPath) {
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
					relationships[id][subID].Add(ownedPath)
				}
			}
		}
	}

	return relationships
}

func allPaths(ownedFilePath string, resolver file.Resolver) []string {
	// though we have a string path, we need to resolve symlinks and other filesystem oddities since we cannot assume this is a real path
	var locs []file.Location
	var err error
	if resolver != nil {
		locs, err = resolver.FilesByPath(ownedFilePath)
		if err != nil {
			log.WithFields("error", err, "path", ownedFilePath).Trace("unable to find path for owned file")
			locs = nil
		}
	}

	ownedFilePaths := strset.New(ownedFilePath)
	for _, loc := range locs {
		ownedFilePaths.Add(loc.RealPath)
	}
	return ownedFilePaths.List()
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
