package binary

import (
	"path"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func NewDependencyRelationships(resolver file.Resolver, accessor sbomsync.Accessor) []artifact.Relationship {
	// TODO: consider library format (e.g. ELF, Mach-O, PE) for the meantime assume all binaries are homogeneous format

	// start with building new package-to-package relationships for executables-to-executables
	// each relationship must be unique, store in a map[id]map[id]relationship to avoid duplicates
	// 1 & 2... build an index of all shared libraries and their owning packages to search against
	index := newShareLibIndex(resolver, accessor)

	// 3. craft package-to-package relationships for each binary that represent shared library dependencies
	//note: we only care about package-to-package relationships
	relIndex := newRelationshipIndex()

	return generateRelationships(resolver, accessor, index, relIndex)
}

func generateRelationships(resolver file.Resolver, accessor sbomsync.Accessor, index *sharedLibraryIndex, relIndex *relationshipIndex) []artifact.Relationship {
	// read all existing dependencyOf relationships
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		for _, r := range s.Relationships {
			if r.Type != artifact.DependencyOfRelationship {
				continue
			}
			relIndex.track(r)
		}
	})

	// find all package-to-package relationships for shared library dependencies
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		for _, parentPkg := range s.Artifacts.Packages.Sorted(pkg.BinaryPkg) {
			for _, evidentLocation := range parentPkg.Locations.ToSlice() {
				if evidentLocation.Annotations[pkg.EvidenceAnnotationKey] != pkg.PrimaryEvidenceAnnotation {
					continue
				}

				// find all libraries that this package depends on
				exec, ok := s.Artifacts.Executables[evidentLocation.Coordinates]
				if !ok {
					continue
				}

				relIndex = populateRelatiionships(exec, parentPkg, resolver, relIndex, index)
			}
		}
	})

	return relIndex.newRelationships()
}

func populateRelatiionships(exec file.Executable, parentPkg pkg.Package, resolver file.Resolver, relIndex *relationshipIndex, index *sharedLibraryIndex) *relationshipIndex {
	for _, libReference := range exec.ImportedLibraries {
		// for each library reference, check s.Artifacts.Packages.Sorted(pkg.BinaryPkg) for a binary package that represents that library
		// if found, create a relationship between the parent package and the library package
		// if not found do nothing.
		// note: we only care about package-to-package relationships

		// find the basename of the library
		libBasename := path.Base(libReference)
		libLocations, err := resolver.FilesByGlob("**/" + libBasename)
		if err != nil {
			log.WithFields("lib", libReference, "error", err).Trace("unable to resolve library basename")
			continue
		}

		for _, loc := range libLocations {
			// are you in our index?
			realBaseName := path.Base(loc.RealPath)
			pkgCollection := index.owningLibraryPackage(realBaseName)

			for _, p := range pkgCollection.Sorted() {
				relIndex.add(
					artifact.Relationship{
						From: p,
						To:   parentPkg,
						Type: artifact.DependencyOfRelationship,
					},
				)
			}
		}
	}
	return relIndex
}
