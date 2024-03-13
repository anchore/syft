package binary

import (
	"path"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func NewDependencyRelationships(resolver file.Resolver, accessor sbomsync.Accessor) []artifact.Relationship {
	// TODO: consider library format (e.g. ELF, Mach-O, PE) for the meantime assume all binaries are homogeneous format

	// start with building new file-to-file relationships for executables-to-executables
	// you need to make certain that they are unique, store in a map[id]map[id]relationship to avoid dupes.
	// before creating the new file-to-file relationship, check to see if there are packages that represent each
	// file. If there are, create a package-to-package, file-to-package, or package-to-file relationship as appropriate.

	// 1 & 2... build an index of all shared libraries and their owning packages to search against
	index := newShareLibIndex(resolver, accessor)

	// 3. craft package-to-package or package-to-file relationships that represent binary shared library dependencies
	// note: prefer package-to-package relationships over package-to-file relationships

	relIndex := newRelationshipIndex()
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		// read all existing dependencyOf relationships
		for _, r := range s.Relationships {
			if r.Type != artifact.DependencyOfRelationship {
				continue
			}
			relIndex.track(r)
		}
	})

	// find all new relationships to add...
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

				for _, libReference := range exec.ImportedLibraries {
					// TODO: is this always a basename? technically no, it could be a path...
					libBasename := path.Base(libReference)

					pkgsThatOwnLib := index.owningLibraryPackage(libBasename)
					if pkgsThatOwnLib == nil {
						// create package-to-file relationship...
						// if there is more than one library for this given library name, then we will include
						// all of them as dependencies since we don't know the LD_LIBRARY_PATH order
						// TODO: add configuration for LD_LIBRARY_PATH order?
						for _, libCoord := range index.owningLibraryLocations(libBasename).ToSlice() {
							relIndex.add(
								artifact.Relationship{
									From: libCoord,
									To:   parentPkg,
									Type: artifact.DependencyOfRelationship,
								},
							)
						}

						// don't create a package-to-package relationship for this library... since we can't
						continue
					}

					// create a package-to-package relationship between the binary package and the library package
					// if there is more than one library for this given library name, then we will include
					// all of them as dependencies since we don't know the LD_LIBRARY_PATH order
					for _, pkgThatOwnsLib := range pkgsThatOwnLib.Sorted() {
						relIndex.add(
							artifact.Relationship{
								From: pkgThatOwnsLib,
								To:   parentPkg,
								Type: artifact.DependencyOfRelationship,
							},
						)
					}
				}
			}
		}
	})

	// so far this handles the first order dependencies from the binary package. Odds are that the OS package manager
	// will have already created a package-to-package relationship for the lib packages to other lib packages.

	return relIndex.newRelationships()
}
