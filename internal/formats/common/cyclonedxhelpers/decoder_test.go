package cyclonedxhelpers

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
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
						PackageURL: "pkg:alpine/alpine-baselayout@3.2.0-r16?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.14.2",
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
						Ref: "p1",
						Dependencies: &[]cyclonedx.Dependency{
							{
								Ref: "p2",
							},
						},
					},
				},
			},
			expected: []expected{
				{
					os:  "debian",
					ver: "1.2.3",
				},
				{
					pkg:      "package-1",
					ver:      "1.0.1",
					cpe:      "cpe:2.3:*:some:package:1:*:*:*:*:*:*:*",
					purl:     "pkg:some/package-1@1.0.1?arch=arm64&upstream=upstream1&distro=alpine-1",
					relation: "package-2",
				},
				{
					pkg:  "package-2",
					ver:  "2.0.2",
					purl: "pkg:alpine/alpine-baselayout@3.2.0-r16?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.14.2",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sbom, err := toSyftModel(&test.input)
			assert.NoError(t, err)

		test:
			for _, e := range test.expected {
				if e.os != "" {
					assert.Equal(t, e.os, sbom.Artifacts.LinuxDistribution.ID)
					assert.Equal(t, e.ver, sbom.Artifacts.LinuxDistribution.VersionID)
				}
				if e.pkg != "" {
					for p := range sbom.Artifacts.PackageCatalog.Enumerate() {
						if e.pkg != p.Name {
							continue
						}

						assert.Equal(t, e.ver, p.Version)

						if e.cpe != "" {
							foundCPE := false
							for _, c := range p.CPEs {
								cstr := c.BindToFmtString()
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
								p := sbom.Artifacts.PackageCatalog.Package(r.To.ID())
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

func Test_missingDataDecode(t *testing.T) {
	bom := &cyclonedx.BOM{
		Metadata:   nil,
		Components: &[]cyclonedx.Component{},
	}

	_, err := toSyftModel(bom)
	assert.NoError(t, err)

	bom.Metadata = &cyclonedx.Metadata{}

	_, err = toSyftModel(bom)
	assert.NoError(t, err)

	pkg := decodeComponent(&cyclonedx.Component{
		Licenses: &cyclonedx.Licenses{
			{
				License: nil,
			},
		},
	})

	assert.Len(t, pkg.Licenses, 0)
}
