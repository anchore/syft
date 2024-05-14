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
	var relIndex *relationshipIndex
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		relIndex = newRelationshipIndex(s.Relationships...)
	})

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

				populateRelationships(exec, parentPkg, resolver, relIndex, index)
			}
		}
	})

	return relIndex.newRelationships()
}

// PackagesToRemove returns a list of binary packages (resolved by the ELF cataloger) that should be removed from the SBOM
// These packages are removed because they are already represented by a higher order packages in the SBOM.
func PackagesToRemove(resolver file.Resolver, accessor sbomsync.Accessor) []artifact.ID {
	pkgsToDelete := make([]artifact.ID, 0)
	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		// OTHER package type > ELF package type > Binary package type
		pkgsToDelete = append(pkgsToDelete, getBinaryPackagesToDelete(resolver, s)...)
		pkgsToDelete = append(pkgsToDelete, compareElfBinaryPackages(s)...)
	})
	return pkgsToDelete
}

func compareElfBinaryPackages(s *sbom.SBOM) []artifact.ID {
	pkgsToDelete := make([]artifact.ID, 0)
	for _, elfPkg := range allElfPackages(s) {
		for _, loc := range onlyPrimaryEvidenceLocations(elfPkg) {
			for _, otherPkg := range s.Artifacts.Packages.PackagesByPath(loc.RealPath) {
				// we only care about comparing binary packages to each other (not other types)
				if otherPkg.Type != pkg.BinaryPkg {
					continue
				}
				if !isElfPackage(otherPkg) {
					pkgsToDelete = append(pkgsToDelete, otherPkg.ID())
				}
			}
		}
	}
	return pkgsToDelete
}

func onlyPrimaryEvidenceLocations(p pkg.Package) []file.Location {
	var locs []file.Location
	for _, loc := range p.Locations.ToSlice() {
		if loc.Annotations[pkg.EvidenceAnnotationKey] != pkg.PrimaryEvidenceAnnotation {
			continue
		}
		locs = append(locs, loc)
	}

	return locs
}

func allElfPackages(s *sbom.SBOM) []pkg.Package {
	var elfPkgs []pkg.Package
	for _, p := range s.Artifacts.Packages.Sorted(pkg.BinaryPkg) {
		if !isElfPackage(p) {
			continue
		}
		elfPkgs = append(elfPkgs, p)
	}
	return elfPkgs
}

func isElfPackage(p pkg.Package) bool {
	_, ok := p.Metadata.(pkg.ELFBinaryPackageNoteJSONPayload)
	return ok
}

func getBinaryPackagesToDelete(resolver file.Resolver, s *sbom.SBOM) []artifact.ID {
	pkgsToDelete := make([]artifact.ID, 0)
	for p := range s.Artifacts.Packages.Enumerate() {
		if p.Type == pkg.BinaryPkg {
			continue
		}
		fileOwner, ok := p.Metadata.(pkg.FileOwner)
		if !ok {
			continue
		}
		ownedFiles := fileOwner.OwnedFiles()
		locations, err := resolver.FilesByPath(ownedFiles...)
		if err != nil {
			log.WithFields("error", err).Trace("unable to find path for owned file")
			continue
		}
		for _, loc := range locations {
			for _, pathPkg := range s.Artifacts.Packages.PackagesByPath(loc.RealPath) {
				if pathPkg.Type == pkg.BinaryPkg {
					pkgsToDelete = append(pkgsToDelete, pathPkg.ID())
				}
			}
		}
	}
	return pkgsToDelete
}

func populateRelationships(exec file.Executable, parentPkg pkg.Package, resolver file.Resolver, relIndex *relationshipIndex, index *sharedLibraryIndex) {
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
			if pkgCollection.PackageCount() < 1 {
				relIndex.add(
					artifact.Relationship{
						From: loc.Coordinates,
						To:   parentPkg,
						Type: artifact.DependencyOfRelationship,
					},
				)
			}
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
}
