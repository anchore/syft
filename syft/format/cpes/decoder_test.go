package cpes

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestDecoder_Decode(t *testing.T) {
	tests := []struct {
		name      string
		userInput string
		sbom      *sbom.SBOM
	}{
		{
			name:      "takes a single cpe",
			userInput: "cpe:/a:apache:log4j:2.14.1",
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name:    "log4j",
						Version: "2.14.1",
						CPEs: []cpe.CPE{
							cpe.Must("cpe:/a:apache:log4j:2.14.1", ""),
						},
					}),
				},
			},
		},
		{
			name: "takes multiple cpes",
			userInput: `cpe:/a:apache:log4j:2.14.1
						cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*;
						cpe:2.3:a:f5:nginx:0.5.2:*:*:*:*:*:*:*;
						cpe:2.3:a:f5:nginx:0.5.3:*:*:*:*:*:*:*;`,
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(
						pkg.Package{
							Name:    "log4j",
							Version: "2.14.1",
							CPEs: []cpe.CPE{
								cpe.Must("cpe:/a:apache:log4j:2.14.1", ""),
							},
						},
						pkg.Package{
							Name:    "nginx",
							Version: "",
							CPEs: []cpe.CPE{
								cpe.Must("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*;", ""),
							},
						},
						pkg.Package{
							Name:    "nginx",
							Version: "0.5.2",
							CPEs: []cpe.CPE{
								cpe.Must("cpe:2.3:a:f5:nginx:0.5.2:*:*:*:*:*:*:*;", ""),
							},
						},
						pkg.Package{
							Name:    "nginx",
							Version: "0.5.3",
							CPEs: []cpe.CPE{
								cpe.Must("cpe:2.3:a:f5:nginx:0.5.3:*:*:*:*:*:*:*;", ""),
							},
						},
					),
				},
			},
		},
		{
			name:      "takes cpe with no version",
			userInput: "cpe:/a:apache:log4j",
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name: "log4j",
						CPEs: []cpe.CPE{
							cpe.Must("cpe:/a:apache:log4j", ""),
						},
					}),
				},
			},
		},
		{
			name:      "takes CPE 2.3 format",
			userInput: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name:    "log4j",
						Version: "2.14.1",
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", ""),
						},
					}),
				},
			},
		},
		{
			name:      "deduces target SW from CPE - known target_sw",
			userInput: "cpe:2.3:a:amazon:opensearch:*:*:*:*:*:ruby:*:*",
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name: "opensearch",
						Type: pkg.GemPkg,
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:amazon:opensearch:*:*:*:*:*:ruby:*:*", ""),
						},
					}),
				},
			},
		},
		{
			name:      "handles unknown target_sw CPE field",
			userInput: "cpe:2.3:a:amazon:opensearch:*:*:*:*:*:loremipsum:*:*",
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(pkg.Package{
						Name: "opensearch",
						Type: "",
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:amazon:opensearch:*:*:*:*:*:loremipsum:*:*", ""),
						},
					}),
				},
			},
		},
		{
			name:      "invalid prefix",
			userInput: "dir:test-fixtures/cpe",
			sbom: &sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(),
				},
			},
		},
	}

	syftPkgOpts := []cmp.Option{
		cmpopts.IgnoreFields(pkg.Package{}, "id", "Language"),
		cmpopts.IgnoreUnexported(pkg.Package{}, file.LocationSet{}, pkg.LicenseSet{}),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := NewFormatDecoder()

			decodedSBOM, _, _, err := dec.Decode(strings.NewReader(tc.userInput))
			require.NoError(t, err)

			gotSyftPkgs := decodedSBOM.Artifacts.Packages.Sorted()
			wantSyftPkgs := tc.sbom.Artifacts.Packages.Sorted()
			require.Equal(t, len(gotSyftPkgs), len(wantSyftPkgs))
			for idx, wantPkg := range wantSyftPkgs {
				if d := cmp.Diff(wantPkg, gotSyftPkgs[idx], syftPkgOpts...); d != "" {
					t.Errorf("unexpected Syft Package (-want +got):\n%s", d)
				}
			}
		})
	}
}
