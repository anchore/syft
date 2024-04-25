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

func TestNewDependencyRelationships(t *testing.T) {
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

	tests := []struct {
		name     string
		resolver file.Resolver
		accessor sbomsync.Accessor
		want     []artifact.Relationship
	}{
		{
			name:     "blank sbom and accessor returns empty relationships",
			resolver: nil,
			accessor: func() sbomsync.Accessor {
				return sbomsync.NewBuilder(&sbom.SBOM{}).(sbomsync.Accessor)
			}(),
			want: make([]artifact.Relationship, 0),
		},
		{
			name: "binary elf cataloger test fixture",
			resolver: file.NewMockResolverForPaths(
				"/usr/lib64/libc.so.6",
				"/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib",
				"/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1",
			),
			accessor: func() sbomsync.Accessor {
				s := sbom.SBOM{
					Artifacts: sbom.Artifacts{
						Packages: pkg.NewCollection(),
					},
				}

				builder := sbomsync.NewBuilder(&s)
				builder.AddPackages(
					glibCPackage,
					syftTestFixturePackage,
				)

				syftTestFixtureLib := file.Coordinates{
					RealPath: "/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib",
				}
				syftTestFixtureLibBin1 := file.Coordinates{
					RealPath: "/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1",
				}
				glibcCoord := file.Coordinates{
					RealPath: "/usr/lib64/libc.so.6",
				}
				syftTestFixtureExecutable := file.Executable{
					Format:        "elf",
					HasExports:    true,
					HasEntrypoint: true,
					ImportedLibraries: []string{
						"libc.so.6",
					},
				}

				accessor := builder.(sbomsync.Accessor)
				accessor.WriteToSBOM(func(s *sbom.SBOM) {
					s.Artifacts.Executables = make(map[file.Coordinates]file.Executable)

					// add the libstdc++ executable
					s.Artifacts.Executables[glibcCoord] = file.Executable{
						Format:            "elf",
						HasExports:        true,
						HasEntrypoint:     true,
						ImportedLibraries: []string{},
					}
					s.Artifacts.Executables[syftTestFixtureLib] = syftTestFixtureExecutable
					s.Artifacts.Executables[syftTestFixtureLibBin1] = syftTestFixtureExecutable
				})

				return accessor
			}(),
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
			relationships := NewDependencyRelationships(tt.resolver, tt.accessor)
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
