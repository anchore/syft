package binary

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// GLIBC [RPM]
// GLIBC [lib executable]
// sytftestfixture [ELF P]
// sytftestfixture (lib executable)... that imports GLIBC

// 1. ELF P (a) --> exec (a) ---> imports of (a) --> (b) executable (imported executable) (ELF P --> file)
// 1... but with symlinks!
// 1. ... but there is no primary evidence
// 1. ... but there is no executable for the ELF package

// 2. ELF P (a) --> exec (a) ---> imports of (a) --> (b) executable (imported executable) --> resolves to RPM package ( ELF P --> RPM)
// 3. ELF P (a) is a part of RPM P (b), thus ELF P (a) is deleted from the SBOM... this means that (b) gets all relationships of (a)

func TestNewDependencyRelationships(t *testing.T) {
	// package discovered in the executable
	glibCPackage := pkg.Package{
		Name:    "glibc",
		Version: "2.28-236.el8_9.12",
		Type:    pkg.RpmPkg,
		Metadata: pkg.RpmDBEntry{
			Files: []pkg.RpmFileRecord{
				{
					Path: "/usr/lib64/libc.so.6",
				},
			},
		},
	}

	// package that is an executable
	syftTestFixturePackage := pkg.Package{
		Name:    "syfttestfixture",
		Version: "0.01",
		PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
		FoundBy: "",
		Locations: file.NewLocationSet(
			file.NewLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
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

	// executable representation of the above binary pkg
	syftTestFixtureExecutable := file.Executable{
		Format:        "elf",
		HasExports:    true,
		HasEntrypoint: true,
		ImportedLibraries: []string{
			"libc.so.6",
		},
	}

	tests := []struct {
		name            string
		resolver        file.Resolver
		coordinateIndex map[file.Coordinates]file.Executable
		packages        []pkg.Package
		want            []artifact.Relationship
	}{
		{
			name:            "blank sbom and accessor returns empty relationships",
			resolver:        nil,
			coordinateIndex: map[file.Coordinates]file.Executable{},
			packages:        []pkg.Package{},
			want:            make([]artifact.Relationship, 0),
		},
		{
			name: "given a package that imports glibC, expect a relationship between the two packages when the package is an executable",
			resolver: file.NewMockResolverForPaths(
				"/usr/lib64/libc.so.6",
				"/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib",
				"/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1",
			),
			// path -> executable (above mock resolver needs to be able to resolve to paths in this map)
			coordinateIndex: map[file.Coordinates]file.Executable{
				{
					RealPath: "/usr/lib64/libc.so.6",
				}: {
					Format:            "elf",
					HasExports:        true,
					HasEntrypoint:     true,
					ImportedLibraries: []string{},
				},
				{
					RealPath: "/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib",
				}: syftTestFixtureExecutable,
				{
					RealPath: "/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1",
				}: syftTestFixtureExecutable,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessor := newAccesorClosure(tt.packages, tt.coordinateIndex)
			// given a resolver that knows about the paths of the packages and executables,
			// and given an SBOM accessor that knows about the packages and executables,
			// we should be able to create a set of relationships between the packages and executables
			relationships := NewDependencyRelationships(tt.resolver, accessor)
			if d := cmp.Diff(tt.want, relationships, cmpopts.IgnoreUnexported(
				pkg.Package{},
				artifact.Relationship{},
				file.LocationSet{},
				pkg.LicenseSet{},
			)); d != "" {
				t.Errorf("unexpected relationships (-want, +got): %s", d)
			}
		})
	}
}

func newAccesorClosure(pkgs []pkg.Package, coordinateIndex map[file.Coordinates]file.Executable) sbomsync.Accessor {
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
	})
	return accessor
}
