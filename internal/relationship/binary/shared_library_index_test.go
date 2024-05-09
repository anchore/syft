package binary

import (
	"path"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_newShareLibIndex(t *testing.T) {
	tests := []struct {
		name                    string
		resolver                file.Resolver
		coordinateIndex         map[file.Coordinates]file.Executable
		packages                []pkg.Package
		prexistingRelationships []artifact.Relationship
	}{
		{
			name:                    "constructor",
			resolver:                file.NewMockResolverForPaths(),
			coordinateIndex:         map[file.Coordinates]file.Executable{},
			packages:                []pkg.Package{},
			prexistingRelationships: []artifact.Relationship{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := newAccessor(tt.packages, tt.coordinateIndex, tt.prexistingRelationships)
			sharedLibraryIndex := newShareLibIndex(tt.resolver, accessor)
			if sharedLibraryIndex == nil {
				t.Errorf("newShareLibIndex() = %v, want non-nil", sharedLibraryIndex)
			}
		})
	}
}

func Test_sharedLibraryIndex_build(t *testing.T) {
	glibcCoordinate := file.NewCoordinates("/usr/lib64/libc.so.6", "")
	secondGlibcCoordinate := file.NewCoordinates("/usr/local/lib64/libc.so.6", "")
	glibcExecutable := file.Executable{
		Format:        "elf",
		HasExports:    true,
		HasEntrypoint: true,
		ImportedLibraries: []string{
			path.Base(glibcCoordinate.RealPath),
			path.Base(secondGlibcCoordinate.RealPath),
		},
	}
	glibCPackage := pkg.Package{
		Name:    "glibc",
		Version: "2.28-236.el8_9.12",
		Locations: file.NewLocationSet(
			file.NewLocation(glibcCoordinate.RealPath),
			file.NewLocation("some/other/path"),
		),
		Type: pkg.RpmPkg,
		Metadata: pkg.RpmDBEntry{
			Files: []pkg.RpmFileRecord{
				{
					Path: glibcCoordinate.RealPath,
				},
				{
					Path: "some/other/path",
				},
			},
		},
	}

	tests := []struct {
		name                    string
		resolver                file.Resolver
		coordinateIndex         map[file.Coordinates]file.Executable
		packages                []pkg.Package
		prexistingRelationships []artifact.Relationship
	}{
		{
			name: "build with locations and packages",
			resolver: file.NewMockResolverForPaths([]string{
				glibcCoordinate.RealPath,
				secondGlibcCoordinate.RealPath,
			}...),
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:       glibcExecutable,
				secondGlibcCoordinate: glibcExecutable,
			},
			packages: []pkg.Package{
				glibCPackage,
			},
			prexistingRelationships: []artifact.Relationship{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := newAccessor(tt.packages, tt.coordinateIndex, tt.prexistingRelationships)
			sharedLibraryIndex := newShareLibIndex(tt.resolver, accessor)
			sharedLibraryIndex.build(tt.resolver, accessor)
			pkgs := sharedLibraryIndex.owningLibraryPackage(path.Base(glibcCoordinate.RealPath))
			if pkgs.PackageCount() < 1 {
				t.Errorf("owningLibraryPackage() = %v, want non-empty", pkgs)
			}
		})
	}
}
