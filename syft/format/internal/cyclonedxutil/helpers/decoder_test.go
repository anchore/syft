package helpers

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func Test_decode(t *testing.T) {
	type expected struct {
		os       string
		pkg      string
		ver      string
		relation string
		purl     string
		cpe      string
	}
	tests := []struct {
		name     string
		input    cyclonedx.BOM
		expected []expected
	}{
		{
			name: "basic mapping from cyclonedx",
			input: cyclonedx.BOM{
				Metadata: nil,
				Components: &[]cyclonedx.Component{
					{
						BOMRef:      "p1",
						Type:        cyclonedx.ComponentTypeLibrary,
						Name:        "package-1",
						Version:     "1.0.1",
						Description: "",
						Hashes:      nil,
						Licenses: &cyclonedx.Licenses{
							{
								License: &cyclonedx.License{
									ID: "MIT",
								},
							},
						},
						CPE:        "cpe:2.3:*:some:package:1:*:*:*:*:*:*:*",
						PackageURL: "pkg:some/package-1@1.0.1?arch=arm64&upstream=upstream1&distro=alpine-1",
						ExternalReferences: &[]cyclonedx.ExternalReference{
							{
								URL:     "",
								Comment: "",
								Hashes:  nil,
								Type:    "",
							},
						},
						Properties: &[]cyclonedx.Property{
							{
								Name:  "foundBy",
								Value: "the-cataloger-1",
							},
							{
								Name:  "language",
								Value: "python",
							},
							{
								Name:  "type",
								Value: "python",
							},
							{
								Name:  "metadataType",
								Value: "PythonPackageMetadata",
							},
							{
								Name:  "path",
								Value: "/some/path/pkg1",
							},
						},
						Components: nil,
						Evidence:   nil,
					},
					{
						BOMRef:  "p2",
						Type:    cyclonedx.ComponentTypeLibrary,
						Name:    "package-2",
						Version: "2.0.2",
						Hashes:  nil,
						Licenses: &cyclonedx.Licenses{
							{
								License: &cyclonedx.License{
									ID: "MIT",
								},
							},
						},
						CPE:        "cpe:2.3:*:another:package:2:*:*:*:*:*:*:*",
						PackageURL: "pkg:apk/alpine/alpine-baselayout@3.2.0-r16?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.14.2",
						Properties: &[]cyclonedx.Property{
							{
								Name:  "foundBy",
								Value: "apkdb-cataloger",
							},
							{
								Name:  "type",
								Value: "apk",
							},
							{
								Name:  "metadataType",
								Value: "ApkMetadata",
							},
							{
								Name:  "path",
								Value: "/lib/apk/db/installed",
							},
							{
								Name:  "layerID",
								Value: "sha256:9fb3aa2f8b8023a4bebbf92aa567caf88e38e969ada9f0ac12643b2847391635",
							},
							{
								Name:  "originPackage",
								Value: "zlib",
							},
							{
								Name:  "size",
								Value: "51213",
							},
							{
								Name:  "installedSize",
								Value: "110592",
							},
							{
								Name:  "pullDependencies",
								Value: "so:libc.musl-x86_64.so.1",
							},
							{
								Name:  "pullChecksum",
								Value: "Q1uss4DfpvL16Nw2YUTwmzGBABz3Y=",
							},
							{
								Name:  "gitCommitOfApkPort",
								Value: "d2bfb22c8e8f67ad7d8d02704f35ec4d2a19f9b9",
							},
						},
					},
					{
						Type:    cyclonedx.ComponentTypeOS,
						Name:    "debian",
						Version: "1.2.3",
						Hashes:  nil,
						Licenses: &cyclonedx.Licenses{
							{
								License: &cyclonedx.License{
									ID: "MIT",
								},
							},
						},
						Properties: &[]cyclonedx.Property{
							{
								Name:  "prettyName",
								Value: "debian",
							},
							{
								Name:  "id",
								Value: "debian",
							},
							{
								Name:  "versionID",
								Value: "1.2.3",
							},
						},
						Components: nil,
						Evidence:   nil,
					},
				},
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref:          "p1",
						Dependencies: &[]string{"p2"},
					},
				},
			},
			expected: []expected{
				{
					os:  "debian",
					ver: "1.2.3",
				},
				{
					pkg:  "package-1",
					ver:  "1.0.1",
					cpe:  "cpe:2.3:*:some:package:1:*:*:*:*:*:*:*",
					purl: "pkg:some/package-1@1.0.1?arch=arm64&upstream=upstream1&distro=alpine-1",
				},
				{
					pkg:      "package-2",
					ver:      "2.0.2",
					purl:     "pkg:apk/alpine/alpine-baselayout@3.2.0-r16?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.14.2",
					relation: "package-1",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sbom, err := ToSyftModel(&test.input)
			assert.NoError(t, err)

		test:
			for _, e := range test.expected {
				if e.os != "" {
					assert.Equal(t, e.os, sbom.Artifacts.LinuxDistribution.ID)
					assert.Equal(t, e.ver, sbom.Artifacts.LinuxDistribution.VersionID)
				}
				if e.pkg != "" {
					for p := range sbom.Artifacts.Packages.Enumerate() {
						if e.pkg != p.Name {
							continue
						}

						assert.Equal(t, e.ver, p.Version)

						if e.cpe != "" {
							foundCPE := false
							for _, c := range p.CPEs {
								cstr := c.Attributes.BindToFmtString()
								if e.cpe == cstr {
									foundCPE = true
									break
								}
							}
							if !foundCPE {
								assert.Fail(t, fmt.Sprintf("CPE not found in package: %s", e.cpe))
							}
						}

						if e.purl != "" {
							assert.Equal(t, e.purl, p.PURL)
						}

						if e.relation != "" {
							foundRelation := false
							for _, r := range sbom.Relationships {
								p := sbom.Artifacts.Packages.Package(r.To.ID())
								if e.relation == p.Name {
									foundRelation = true
									break
								}
							}
							if !foundRelation {
								assert.Fail(t, fmt.Sprintf("relation not found: %s", e.relation))
							}
						}
						continue test
					}
					assert.Fail(t, fmt.Sprintf("package should be present: %s", e.pkg))
				}
			}
		})
	}
}

func Test_relationshipDirection(t *testing.T) {
	cyclonedx_bom := cyclonedx.BOM{Metadata: nil,
		Components: &[]cyclonedx.Component{
			{
				BOMRef:     "p1",
				Type:       cyclonedx.ComponentTypeLibrary,
				Name:       "package-1",
				Version:    "1.0.1",
				PackageURL: "pkg:some/package-1@1.0.1?arch=arm64&upstream=upstream1&distro=alpine-1",
			},
			{
				BOMRef:     "p2",
				Type:       cyclonedx.ComponentTypeLibrary,
				Name:       "package-2",
				Version:    "2.0.2",
				PackageURL: "pkg:some/package-2@2.0.2?arch=arm64&upstream=upstream1&distro=alpine-1",
			},
		},
		Dependencies: &[]cyclonedx.Dependency{
			{
				Ref:          "p1",
				Dependencies: &[]string{"p2"},
			},
		}}
	sbom, err := ToSyftModel(&cyclonedx_bom)
	assert.Nil(t, err)
	assert.Len(t, sbom.Relationships, 1)
	relationship := sbom.Relationships[0]

	// check that p2 -- dependency of --> p1
	// same as p1 -- depends on --> p2
	assert.Equal(t, artifact.DependencyOfRelationship, relationship.Type)
	assert.Equal(t, "package-2", packageNameFromIdentifier(sbom, relationship.From))
	assert.Equal(t, "package-1", packageNameFromIdentifier(sbom, relationship.To))
}

func packageNameFromIdentifier(model *sbom.SBOM, identifier artifact.Identifiable) string {
	return model.Artifacts.Packages.Package(identifier.ID()).Name
}

func Test_missingDataDecode(t *testing.T) {
	bom := &cyclonedx.BOM{
		Metadata:    nil,
		Components:  &[]cyclonedx.Component{},
		SpecVersion: cyclonedx.SpecVersion1_4,
	}

	_, err := ToSyftModel(bom)
	assert.NoError(t, err)

	bom.Metadata = &cyclonedx.Metadata{}

	_, err = ToSyftModel(bom)
	assert.NoError(t, err)

	pkg := decodeComponent(&cyclonedx.Component{
		Licenses: &cyclonedx.Licenses{
			{
				License: nil,
			},
		},
	})
	assert.Equal(t, pkg.Licenses.Empty(), true)
}

func Test_decodeDependencies(t *testing.T) {
	c1 := cyclonedx.Component{
		Name: "c1",
	}

	c2 := cyclonedx.Component{
		Name: "c2",
	}

	c3 := cyclonedx.Component{
		Name: "c3",
	}

	for _, c := range []*cyclonedx.Component{&c1, &c2, &c3} {
		c.BOMRef = c.Name
	}

	setTypes := func(typ cyclonedx.ComponentType, components ...cyclonedx.Component) *[]cyclonedx.Component {
		var out []cyclonedx.Component
		for _, c := range components {
			c.Type = typ
			out = append(out, c)
		}
		return &out
	}

	tests := []struct {
		name     string
		sbom     cyclonedx.BOM
		expected []string
	}{
		{
			name: "dependencies decoded as dependencyOf relationships",
			sbom: cyclonedx.BOM{
				Components: setTypes(cyclonedx.ComponentTypeLibrary,
					c1,
					c2,
					c3,
				),
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref: c1.BOMRef,
						Dependencies: &[]string{
							c2.BOMRef,
							c3.BOMRef,
						},
					},
				},
			},
			expected: []string{c2.Name, c3.Name},
		},
		{
			name: "dependencies skipped with unhandled components",
			sbom: cyclonedx.BOM{
				Components: setTypes("",
					c1,
					c2,
					c3,
				),
				Dependencies: &[]cyclonedx.Dependency{
					{
						Ref: c1.BOMRef,
						Dependencies: &[]string{
							c2.BOMRef,
							c3.BOMRef,
						},
					},
				},
			},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, err := ToSyftModel(&test.sbom)
			require.NoError(t, err)
			require.NotNil(t, s)

			var deps []string
			if s != nil {
				for _, r := range s.Relationships {
					if r.Type != artifact.DependencyOfRelationship {
						continue
					}
					if p, ok := r.To.(pkg.Package); !ok || p.Name != c1.Name {
						continue
					}
					if p, ok := r.From.(pkg.Package); ok {
						deps = append(deps, p.Name)
					}
				}
			}
			require.Equal(t, test.expected, deps)
		})
	}
}
