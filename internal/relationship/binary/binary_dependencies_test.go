package binary

import (
	"path"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestPackagesToRemove(t *testing.T) {
	glibcCoordinate := file.NewCoordinates("/usr/lib64/libc.so.6", "")
	glibCPackage := pkg.Package{
		Name:    "glibc",
		Version: "2.28-236.el8_9.12",
		Locations: file.NewLocationSet(
			file.NewLocation(glibcCoordinate.RealPath),
		),
		Type: pkg.RpmPkg,
		Metadata: pkg.RpmDBEntry{
			Files: []pkg.RpmFileRecord{
				{
					Path: glibcCoordinate.RealPath,
				},
			},
		},
	}
	glibCPackage.SetID()

	glibCBinaryELFPackage := pkg.Package{
		Name: "glibc",
		Locations: file.NewLocationSet(
			file.NewLocation(glibcCoordinate.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type: pkg.BinaryPkg,
		Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
			Type:       "testfixture",
			Vendor:     "syft",
			System:     "syftsys",
			SourceRepo: "https://github.com/someone/somewhere.git",
			Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
		},
	}
	glibCBinaryELFPackage.SetID()

	glibCBinaryELFPackageAsRPM := pkg.Package{
		Name: "glibc",
		Locations: file.NewLocationSet(
			file.NewLocation(glibcCoordinate.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type: pkg.RpmPkg, // note: the elf package claims it is a RPM, not binary
		Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
			Type:       "rpm",
			Vendor:     "syft",
			System:     "syftsys",
			SourceRepo: "https://github.com/someone/somewhere.git",
			Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
		},
	}
	glibCBinaryELFPackageAsRPM.SetID()

	glibCBinaryClassifierPackage := pkg.Package{
		Name: "glibc",
		Locations: file.NewLocationSet(
			file.NewLocation(glibcCoordinate.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
		),
		Type:     pkg.BinaryPkg,
		Metadata: pkg.BinarySignature{},
	}
	glibCBinaryClassifierPackage.SetID()

	libCBinaryClassifierPackage := pkg.Package{
		Name: "libc",
		Locations: file.NewLocationSet(
			file.NewLocation(glibcCoordinate.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type:     pkg.BinaryPkg,
		Metadata: pkg.BinarySignature{},
	}
	libCBinaryClassifierPackage.SetID()

	tests := []struct {
		name     string
		resolver file.Resolver
		accessor sbomsync.Accessor
		want     []artifact.ID
	}{
		{
			name:     "remove packages that are overlapping rpm --> binary",
			resolver: file.NewMockResolverForPaths(glibcCoordinate.RealPath),
			accessor: newAccessor([]pkg.Package{glibCPackage, glibCBinaryELFPackage}, map[file.Coordinates]file.Executable{}, nil),
			want:     []artifact.ID{glibCBinaryELFPackage.ID()},
		},
		{
			name:     "keep packages that are overlapping rpm --> binary when the binary self identifies as an RPM",
			resolver: file.NewMockResolverForPaths(glibcCoordinate.RealPath),
			accessor: newAccessor([]pkg.Package{glibCPackage, glibCBinaryELFPackageAsRPM}, map[file.Coordinates]file.Executable{}, nil),
			want:     []artifact.ID{},
		},
		{
			name:     "remove no packages when there is a single binary package (or self identifying RPM)",
			resolver: file.NewMockResolverForPaths(glibcCoordinate.RealPath),
			accessor: newAccessor([]pkg.Package{glibCBinaryELFPackage, glibCBinaryELFPackageAsRPM}, map[file.Coordinates]file.Executable{}, nil),
			want:     []artifact.ID{},
		},
		{
			name:     "remove packages when there is a single binary package and a classifier package",
			resolver: file.NewMockResolverForPaths(glibcCoordinate.RealPath),
			accessor: newAccessor([]pkg.Package{glibCBinaryELFPackage, glibCBinaryClassifierPackage}, map[file.Coordinates]file.Executable{}, nil),
			want:     []artifact.ID{glibCBinaryClassifierPackage.ID()},
		},
		{
			name:     "ensure we're considering ELF packages, not just binary packages (supporting evidence)",
			resolver: file.NewMockResolverForPaths(glibcCoordinate.RealPath),
			accessor: newAccessor([]pkg.Package{glibCBinaryClassifierPackage}, map[file.Coordinates]file.Executable{}, nil),
			want:     []artifact.ID{},
		},
		{
			name:     "ensure we're considering ELF packages, not just binary packages (primary evidence)",
			resolver: file.NewMockResolverForPaths(glibcCoordinate.RealPath),
			accessor: newAccessor([]pkg.Package{libCBinaryClassifierPackage}, map[file.Coordinates]file.Executable{}, nil),
			want:     []artifact.ID{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgsToDelete := PackagesToRemove(tt.resolver, tt.accessor)
			if diff := cmp.Diff(tt.want, pkgsToDelete); diff != "" {
				t.Errorf("unexpected packages to delete (-want, +got): %s", diff)
			}
		})
	}
}

func TestNewDependencyRelationships(t *testing.T) {
	// coordinates for the files under test
	glibcCoordinate := file.NewCoordinates("/usr/lib64/libc.so.6", "")
	secondGlibcCoordinate := file.NewCoordinates("/usr/local/lib64/libc.so.6", "")
	nestedLibCoordinate := file.NewCoordinates("/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib", "")
	parallelLibCoordinate := file.NewCoordinates("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1", "")

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
			file.NewLocation(parallelLibCoordinate.RealPath).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation),
		),
		Language: "",
		Type:     pkg.RpmPkg,
		Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
			Type:       "rpm",
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
		},
		{
			name: "given a package that imports glibc, expect a relationship between the two packages when the package is an executable",
			resolver: file.NewMockResolverForPaths(
				glibcCoordinate.RealPath,
				nestedLibCoordinate.RealPath,
				parallelLibCoordinate.RealPath,
			),
			// path -> executable (above mock resolver needs to be able to resolve to paths in this map)
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:       glibcExecutable,
				nestedLibCoordinate:   syftTestFixtureExecutable,
				parallelLibCoordinate: syftTestFixtureExecutable2,
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
				parallelLibCoordinate.RealPath,
			),
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:       glibcExecutable,
				secondGlibcCoordinate: glibcExecutable,
				nestedLibCoordinate:   syftTestFixtureExecutable,
				parallelLibCoordinate: syftTestFixtureExecutable2,
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
				parallelLibCoordinate.RealPath,
			),
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:       glibcExecutable,
				nestedLibCoordinate:   syftTestFixtureExecutable,
				parallelLibCoordinate: syftTestFixtureExecutable2,
			},
			packages: []pkg.Package{glibCPackage, glibCustomPackage, syftTestFixturePackage},
			prexistingRelationships: []artifact.Relationship{
				{
					From: glibCPackage,
					To:   syftTestFixturePackage,
					Type: artifact.DependencyOfRelationship,
				},
			},
		},
		{
			name:     "given a package that imports a library that is not tracked by the resolver, expect no relationships to be created",
			resolver: file.NewMockResolverForPaths(),
			coordinateIndex: map[file.Coordinates]file.Executable{
				glibcCoordinate:       glibcExecutable,
				nestedLibCoordinate:   syftTestFixtureExecutable,
				parallelLibCoordinate: syftTestFixtureExecutable2,
			},
			packages: []pkg.Package{glibCPackage, syftTestFixturePackage},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := newAccessor(tt.packages, tt.coordinateIndex, tt.prexistingRelationships)
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
	), cmpopts.SortSlices(lessRelationships))
}

func lessRelationships(r1, r2 artifact.Relationship) bool {
	c := strings.Compare(string(r1.Type), string(r2.Type))
	if c != 0 {
		return c < 0
	}
	c = strings.Compare(string(r1.From.ID()), string(r2.From.ID()))
	if c != 0 {
		return c < 0
	}
	c = strings.Compare(string(r1.To.ID()), string(r2.To.ID()))
	return c < 0
}

func newAccessor(pkgs []pkg.Package, coordinateIndex map[file.Coordinates]file.Executable, preexistingRelationships []artifact.Relationship) sbomsync.Accessor {
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
		if preexistingRelationships != nil {
			s.Relationships = preexistingRelationships
		}
	})
	return accessor
}
