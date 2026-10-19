package binary

import (
	"path"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

type sharedLibraryIndex struct {
	libLocationsByBasename map[string]file.CoordinateSet
	allLibLocations        file.CoordinateSet
	packagesByLibraryPath  map[file.Coordinates]*pkg.Collection
}

func newShareLibIndex(resolver file.Resolver, accessor sbomsync.Accessor) *sharedLibraryIndex {
	s := &sharedLibraryIndex{
		libLocationsByBasename: make(map[string]file.CoordinateSet),
		allLibLocations:        file.NewCoordinateSet(),
		packagesByLibraryPath:  make(map[file.Coordinates]*pkg.Collection),
	}

	s.build(resolver, accessor)

	return s
}

func (i *sharedLibraryIndex) build(resolver file.Resolver, accessor sbomsync.Accessor) {
	// 1. map out all locations that provide libraries (indexed by the basename)
	i.libLocationsByBasename, i.allLibLocations = locationsThatProvideLibraries(accessor)

	// 2. for each library path, find all packages that claim ownership of the library
	i.packagesByLibraryPath = packagesWithLibraryOwnership(resolver, accessor, i.allLibLocations)
}

func (i *sharedLibraryIndex) owningLibraryPackage(libraryBasename string) *pkg.Collection {
	// find all packages that own a library by its basename
	collection := pkg.NewCollection()
	if set, ok := i.libLocationsByBasename[libraryBasename]; ok {
		for _, coord := range set.ToSlice() {
			if pkgSet, ok := i.packagesByLibraryPath[coord]; ok {
				toAdd := pkgSet.Sorted()
				collection.Add(toAdd...)
			}
		}
	}

	return collection
}

func locationsThatProvideLibraries(accessor sbomsync.Accessor) (map[string]file.CoordinateSet, file.CoordinateSet) {
	// map out all locations that provide libraries (indexed by the basename)
	libLocationsByBasename := make(map[string]file.CoordinateSet)
	allLibLocations := file.NewCoordinateSet()

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		// PROBLEM: this does not consider all symlinks to real paths that are libraries
		for coord, f := range s.Artifacts.Executables {
			if !f.HasExports {
				continue
			}

			basename := path.Base(coord.FullNestedPath())
			set := libLocationsByBasename[basename]
			set.Add(coord)
			allLibLocations.Add(coord)
			libLocationsByBasename[basename] = set
		}
	})

	return libLocationsByBasename, allLibLocations
}
func packagesWithLibraryOwnership(resolver file.Resolver, accessor sbomsync.Accessor, allLibLocations file.CoordinateSet) map[file.Coordinates]*pkg.Collection {
	// map out all packages that claim ownership of a library at a specific path
	packagesByLibraryPath := make(map[file.Coordinates]*pkg.Collection)

	accessor.ReadFromSBOM(func(s *sbom.SBOM) {
		for _, p := range s.Artifacts.Packages.Sorted() {
			var ownedFilePaths []string
			if p.Type == pkg.BinaryPkg {
				for _, loc := range p.Locations.ToSlice() {
					if archive.ContainerPath(loc.Coordinates) != "" {
						// a path within an archive cannot be resolved from the scan root; the location is the library
						addLibraryOwner(packagesByLibraryPath, allLibLocations, loc.Coordinates, p)
						continue
					}
					ownedFilePaths = append(ownedFilePaths, loc.Path())
				}
			} else {
				fileOwner, ok := p.Metadata.(pkg.FileOwner)
				if !ok {
					continue
				}
				ownedFilePaths = fileOwner.OwnedFiles()
			}

			packagesByLibraryPath = populatePackagesByLibraryPath(resolver, allLibLocations, packagesByLibraryPath, p, ownedFilePaths)
		}
	})

	return packagesByLibraryPath
}

func populatePackagesByLibraryPath(
	resolver file.Resolver,
	allLibLocations file.CoordinateSet,
	packagesByLibraryPath map[file.Coordinates]*pkg.Collection,
	p pkg.Package,
	ownedFilePaths []string,
) map[file.Coordinates]*pkg.Collection {
	for _, pth := range ownedFilePaths {
		ownedLocation, err := resolver.FilesByPath(pth)
		if err != nil {
			log.WithFields("error", err, "path", pth).Trace("unable to find path for owned file")
			continue
		}

		for _, loc := range ownedLocation {
			addLibraryOwner(packagesByLibraryPath, allLibLocations, loc.Coordinates, p)
		}
	}
	return packagesByLibraryPath
}

// addLibraryOwner records p as an owner of the file at coordinates when that file is a library.
func addLibraryOwner(packagesByLibraryPath map[file.Coordinates]*pkg.Collection, allLibLocations file.CoordinateSet, coordinates file.Coordinates, p pkg.Package) {
	if !allLibLocations.Contains(coordinates) {
		return
	}
	if _, ok := packagesByLibraryPath[coordinates]; !ok {
		packagesByLibraryPath[coordinates] = pkg.NewCollection()
	}
	packagesByLibraryPath[coordinates].Add(p)
}
