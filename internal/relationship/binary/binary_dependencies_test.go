package binary

import (
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestNewDependencyRelationships(t *testing.T) {
	// coordinates for the files under test
	glibcCoordinate := file.NewCoordinates("/usr/lib64/libc.so.6", "")
	secondGlibcCoordinate := file.NewCoordinates("/usr/local/lib64/libc.so.6", "")
	nestedLibCoordinate := file.NewCoordinates("/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib", "")
	parrallelLibCoordinate := file.NewCoordinates("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1", "")

	// rpm package that was discovered in linked section of the ELF binary package
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
	glibCPackage.SetID()

	// second rpm package that could be discovered in linked section of the ELF binary package (same base path as above)
	glibCustomPackage := pkg.Package{
		Name:      "glibc",
		Version:   "2.28-236.el8_9.12",
		Locations: file.NewLocationSet(file.NewLocation(secondGlibcCoordinate.RealPath)),
		Type:      pkg.RpmPkg,
		Metadata: pkg.RpmDBEntry{
			Files: []pkg.RpmFileRecord{
				{
					Path: secondGlibcCoordinate.RealPath,
				},
			},
		},
	}
	glibCustomPackage.SetID()

	// binary package that is an executable that can link against above rpm packages
	syftTestFixturePackage := pkg.Package{
		Name:    "syfttestfixture",
		Version: "0.01",
		PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
		FoundBy: "",
		Locations: file.NewLocationSet(
			file.NewLocation(nestedLibCoordinate.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			file.NewLocation(parrallelLibCoordinate.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
		),
		Language: "",
		Type:     pkg.BinaryPkg,
		Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
			Type:       "testfixture",
			Vendor:     "syft",
			System:     "syftsys",
			SourceRepo: "https://github.com/someone/somewhere.git",
			Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
		},
	}
	syftTestFixturePackage.SetID()

	// dummy executable representation of glibc
	glibcExecutable := file.Executable{
		Format:            "elf",
		HasExports:        true,
		HasEntrypoint:     true,
		ImportedLibraries: []string{},
	}

	// executable representation of the syftTestFixturePackage
	syftTestFixtureExecutable := file.Executable{
		Format:        "elf",
		HasExports:    true,
		HasEntrypoint: true,
		ImportedLibraries: []string{
			path.Base(glibcCoordinate.RealPath),
		},
	}

	// second executable representation that has no parent package
	syftTestFixtureExecutable2 := file.Executable{
		Format:        "elf",
		HasExports:    true,
		HasEntrypoint: true,
		ImportedLibraries: []string{
			// this should not be a relationship because it is not a coordinate
			"foo.so.6",
		},
	}

	tests := []struct {
		name                    string
		resolver                file.Resolver
		coordinateIndex         map[file.Coordinates]file.Executable
		packages                []pkg.Package
		prexistingRelationships []artifact.Relationship
		want                    []artifact.Relationship
	}{
		{
			name:            "blank sbom and accessor returns empty relationships",
			resolver:        nil,
			coordinateIndex: map[file.Coordinates]file.Executable{},
			packages:        []pkg.Package{},
			want:            make([]artifact.Relationship, 0),
		},
		{
			name: "given a package that imports glibc, expect a relationship between the two packages when the package is an executable",
			resolver: file.NewMockResolverForPaths(
				glibcCoordinate.RealPath,
				nestedLibCoordinate.RealPath,
				parrallelLibCoordinate.RealPath,
			),
			// path -> executable (above mock resolver needs to be able to resolve to paths in this map)
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:        glibcExecutable,
				nestedLibCoordinate:    syftTestFixtureExecutable,
				parrallelLibCoordinate: syftTestFixtureExecutable2,
			},
			packages: []pkg.Package{glibCPackage, syftTestFixturePackage},
			want: []artifact.Relationship{
				{
					From: glibCPackage,
					To:   syftTestFixturePackage,
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
		{
			name: "given an executable maps to one base path represented by two RPM we make two relationships",
			resolver: file.NewMockResolverForPaths(
				glibcCoordinate.RealPath,
				secondGlibcCoordinate.RealPath,
				nestedLibCoordinate.RealPath,
				parrallelLibCoordinate.RealPath,
			),
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:        glibcExecutable,
				secondGlibcCoordinate:  glibcExecutable,
				nestedLibCoordinate:    syftTestFixtureExecutable,
				parrallelLibCoordinate: syftTestFixtureExecutable2,
			},
			packages: []pkg.Package{glibCPackage, glibCustomPackage, syftTestFixturePackage},
			want: []artifact.Relationship{
				{
					From: glibCPackage,
					To:   syftTestFixturePackage,
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: glibCustomPackage,
					To:   syftTestFixturePackage,
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
		{
			name: "given some dependency relationships already exist, expect no duplicate relationships to be created",
			resolver: file.NewMockResolverForPaths(
				glibcCoordinate.RealPath,
				nestedLibCoordinate.RealPath,
				parrallelLibCoordinate.RealPath,
			),
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:        glibcExecutable,
				nestedLibCoordinate:    syftTestFixtureExecutable,
				parrallelLibCoordinate: syftTestFixtureExecutable2,
			},
			packages: []pkg.Package{glibCPackage, glibCustomPackage, syftTestFixturePackage},
			prexistingRelationships: []artifact.Relationship{
				{
					From: glibCPackage,
					To:   syftTestFixturePackage,
					Type: artifact.DependencyOfRelationship,
				},
			},
			want: []artifact.Relationship{},
		},
		{
			name:     "given a package that imports a library that is not tracked by the resolver, expect no relationships to be created",
			resolver: file.NewMockResolverForPaths(),
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:        glibcExecutable,
				nestedLibCoordinate:    syftTestFixtureExecutable,
				parrallelLibCoordinate: syftTestFixtureExecutable2,
			},
			packages: []pkg.Package{glibCPackage, syftTestFixturePackage},
			want:     []artifact.Relationship{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := newAccesor(tt.packages, tt.coordinateIndex, tt.prexistingRelationships)
			// given a resolver that knows about the paths of the packages and executables,
			// and given an SBOM accessor that knows about the packages and executables,
			// we should be able to create a set of relationships between the packages and executables
			relationships := NewDependencyRelationships(tt.resolver, accessor)
			if diff := relationshipComparer(tt.want, relationships); diff != "" {
				t.Errorf("unexpected relationships (-want, +got): %s", diff)
			}
		})
	}
}

func relationshipComparer(x, y []artifact.Relationship) string {
	return cmp.Diff(x, y, cmpopts.IgnoreUnexported(
		pkg.Package{},
		artifact.Relationship{},
		file.LocationSet{},
		pkg.LicenseSet{},
	))
}

func newAccesor(pkgs []pkg.Package, coordinateIndex map[file.Coordinates]file.Executable, prexistingRelationships []artifact.Relationship) sbomsync.Accessor {
	sb := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	builder := sbomsync.NewBuilder(&sb)
	builder.AddPackages(pkgs...)

	accessor := builder.(sbomsync.Accessor)
	accessor.WriteToSBOM(func(s *sbom.SBOM) {
		s.Artifacts.Executables = coordinateIndex
		if prexistingRelationships != nil {
			s.Relationships = prexistingRelationships
		}
	})
	return accessor
}
