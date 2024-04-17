package binary

import (
	"github.com/google/go-cmp/cmp"
	"testing"

	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

func TestNewDependencyRelationships(t *testing.T) {

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
		//{
		//	name:     "binary elf cataloger test fixture",
		//	resolver: nil,
		//	accessor: func() sbomsync.Accessor {
		//		s := sbom.SBOM{
		//			Artifacts: sbom.Artifacts{
		//				Packages: pkg.NewCollection(),
		//			},
		//		}
		//		builder := sbomsync.NewBuilder(&s)
		//
		//		// add ELF packages
		//		builder.AddPackages(
		//			[]pkg.Package{
		//				{
		//					Name:    "glibc",
		//					Version: "2.28-236.el8_9.12",
		//					Type:    pkg.RpmPkg,
		//					Metadata: pkg.RpmDBEntry{
		//						Files: []pkg.RpmFileRecord{
		//							// TODO...?
		//						},
		//					},
		//				},
		//				{
		//					Name:    "libstdc++",
		//					Version: "8.5.0-20.el8",
		//					Type:    pkg.RpmPkg,
		//					Metadata: pkg.RpmDBEntry{
		//						Files: []pkg.RpmFileRecord{
		//							// TODO...?
		//						},
		//					},
		//				},
		//				{
		//					Name:    "libhello_world.so",
		//					Version: "0.01",
		//					PURL:    "pkg:generic/syftsys/libhello_world.so@0.01",
		//					FoundBy: "",
		//					Locations: file.NewLocationSet(
		//						file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so"),
		//						file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so"),
		//						file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so"),
		//					),
		//					Language: "",
		//					Type:     pkg.BinaryPkg,
		//					Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
		//						Type:       "testfixture",
		//						Vendor:     "syft",
		//						System:     "syftsys",
		//						SourceRepo: "https://github.com/someone/somewhere.git",
		//						Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
		//					},
		//				},
		//				{
		//					Name:    "syfttestfixture",
		//					Version: "0.01",
		//					PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
		//					FoundBy: "",
		//					Locations: file.NewLocationSet(
		//						file.NewLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		//						file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		//						file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin2").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		//					),
		//					Language: "",
		//					Type:     pkg.BinaryPkg,
		//					Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
		//						Type:       "testfixture",
		//						Vendor:     "syft",
		//						System:     "syftsys",
		//						SourceRepo: "https://github.com/someone/somewhere.git",
		//						Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
		//					},
		//				},
		//			}...)
		//
		//		// add executables
		//
		//		libstdcCoord := file.Coordinates{
		//			RealPath: "/usr/lib64/libstdc++.so.6.0.25",
		//		}
		//
		//		glibcCoord := file.Coordinates{
		//			RealPath: "/usr/lib64/libc.so.6",
		//		}
		//
		//		accessor := builder.(sbomsync.Accessor)
		//		accessor.WriteToSBOM(func(s *sbom.SBOM) {
		//			// add the libstdc++ executable
		//			s.Artifacts.Executables[libstdcCoord] = file.Executable{
		//				Format:        "elf",
		//				HasExports:    true,
		//				HasEntrypoint: true,
		//				ImportedLibraries: []string{
		//					"libm.so.6",
		//					"libc.so.6",
		//					"ld-linux-aarch64.so.1",
		//					"libgcc_s.so.1",
		//				},
		//			}
		//		})
		//
		//		return accessor
		//	}(),
		//	want: []artifact.Relationship{},
		//},
		//{
		//	name:     "binary elf cataloger test fixture",
		//	resolver: nil,
		//	accessor: func() sbomsync.Accessor {
		//		s := sbom.SBOM{
		//			Artifacts: sbom.Artifacts{
		//				Packages: pkg.NewCollection(),
		//			},
		//		}
		//		builder := sbomsync.NewBuilder(&s)
		//
		//		fixtureName := "elf-test-fixtures"
		//		img := imagetest.GetFixtureImage(t, "docker-archive", fixtureName)
		//
		//		src := stereoscopesource.New(img, stereoscopesource.ImageConfig{
		//			Reference: fixtureName,
		//		})
		//
		//		r, err := src.FileResolver(source.SquashedScope)
		//		require.NoError(t, err)
		//
		//		cat := binary.NewELFPackageCataloger()
		//		pkgs, relationships, err := cat.Catalog(context.Background(), r)
		//		require.NoError(t, err)
		//
		//		builder.AddPackages(pkgs...)
		//		builder.AddRelationships(relationships...)
		//
		//		return builder.(sbomsync.Accessor)
		//	}(),
		//	want: []artifact.Relationship{},
		//},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relationships := NewDependencyRelationships(tt.resolver, tt.accessor)
			if d := cmp.Diff(tt.want, relationships); d != "" {
				t.Errorf("unexpected relationships (-want, +got): %s", d)
			}
		})
	}
}
