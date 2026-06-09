package javascript

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseBunLock_Simple(t *testing.T) {
	fixture := "testdata/bun-lock/simple/bun.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expectedPkgs := []pkg.Package{
		{
			Name:      "ansi-regex",
			Version:   "3.0.1",
			PURL:      "pkg:npm/ansi-regex@3.0.1",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-+O9Jct8wf++lXxxFc4hc8LsjaSq0HFzzL7cVsw8pRDIPdjKD2mT4ytDZlLuSBZ4cLKZFXIrMGO7DbQCtMJJMKw==",
			},
		},
		{
			Name:      "cowsay",
			Version:   "1.6.0",
			PURL:      "pkg:npm/cowsay@1.6.0",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-8C4H1jdrgNusTQr3Yu4SCm+ZKsAlDFbpa0KS0Z3im8ueag+9pGOf3CrioruvmeaW/A5oqg9L0ar6qeftAh03jw==",
				Dependencies: map[string]string{
					"ansi-regex": "^3.0.0",
				},
			},
		},
		{
			Name:      "zod",
			Version:   "3.25.76",
			PURL:      "pkg:npm/zod@3.25.76",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-gzUt/qt81nXsFGKIFcC3YnfEAx5NkunCfnDlvuBSSFS02bcXu4Lmea0AFIUwbLWxWPx3d9p8S5QoaujKcNQxcQ==",
			},
		},
	}

	expectedRels := []artifact.Relationship{
		{
			From: expectedPkgs[0], // ansi-regex
			To:   expectedPkgs[1], // cowsay
			Type: artifact.DependencyOfRelationship,
		},
	}

	adapter := newGenericBunLockAdapter(CatalogerConfig{})
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/bun-lock/simple").
		FromFile(t, fixture).
		Expects(expectedPkgs, expectedRels).
		TestParser(t, adapter.parseBunLock)
}

func TestParseBunLock_ScopedAndPeer(t *testing.T) {
	fixture := "testdata/bun-lock/scoped-and-peer/bun.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@types/node",
			Version:   "20.19.39",
			PURL:      "pkg:npm/%40types/node@20.19.39",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-orrrD74MBUyK8jOAD/r0+lfa1I2MO6I+vAkmAWzMYbCcgrN4lCrmK52gRFQq/JRxfYPfonkr4b0jcY7Olqdqbw==",
				Dependencies: map[string]string{
					"undici-types": "~6.21.0",
				},
			},
		},
		{
			Name:      "loose-envify",
			Version:   "1.4.0",
			PURL:      "pkg:npm/loose-envify@1.4.0",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-lyuxPGr/Wfhrlem2CL/UcnUc1zcqKAImBDzukY7Y5F/yQiNdko6+fRLevlw1HgMySw7f611UIY408EtxRSoK3Q==",
				Dependencies: map[string]string{
					"js-tokens": "^3.0.0 || ^4.0.0",
				},
			},
		},
		{
			Name:      "react",
			Version:   "18.3.1",
			PURL:      "pkg:npm/react@18.3.1",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-wS+hAgJShR0KhEvPJArfuPVN1+Hz1t0Y6n5jLrGQbkb4urgPE/0Rve+1kMB1v/oWgHgm4WIcV+i7F2pTVj+2iQ==",
				Dependencies: map[string]string{
					"loose-envify": "^1.1.0",
				},
			},
		},
		{
			Name:      "undici-types",
			Version:   "6.21.0",
			PURL:      "pkg:npm/undici-types@6.21.0",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-iwDZqg0QAGrg9Rav5H4n0M64c3mkR59cJ6wQp+7C4nI0gsmExaedaYLNO44eT4AtBBwjbTiGPMlt2Md0T9H9JQ==",
			},
		},
	}

	expectedRels := []artifact.Relationship{
		{
			From: expectedPkgs[1], // loose-envify
			To:   expectedPkgs[2], // react
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: expectedPkgs[3], // undici-types
			To:   expectedPkgs[0], // @types/node
			Type: artifact.DependencyOfRelationship,
		},
	}

	adapter := newGenericBunLockAdapter(CatalogerConfig{})
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/bun-lock/scoped-and-peer").
		FromFile(t, fixture).
		Expects(expectedPkgs, expectedRels).
		TestParser(t, adapter.parseBunLock)
}

func TestParseBunLock_DevDependencies(t *testing.T) {
	tests := []struct {
		name       string
		includeDev bool
		expected   func(file.LocationSet) ([]pkg.Package, []artifact.Relationship)
	}{
		{
			name:       "exclude dev (default) drops dev-only transitives but keeps shared",
			includeDev: false,
			expected: func(locations file.LocationSet) ([]pkg.Package, []artifact.Relationship) {
				pkgs := []pkg.Package{
					{
						Name:      "prod-pkg",
						Version:   "1.0.0",
						PURL:      "pkg:npm/prod-pkg@1.0.0",
						Locations: locations,
						Language:  pkg.JavaScript,
						Type:      pkg.NpmPkg,
						Metadata: pkg.BunLockEntry{
							Integrity: "sha512-prod==",
							Dependencies: map[string]string{
								"shared-pkg": "^1.0.0",
							},
						},
					},
					{
						Name:      "shared-pkg",
						Version:   "1.0.0",
						PURL:      "pkg:npm/shared-pkg@1.0.0",
						Locations: locations,
						Language:  pkg.JavaScript,
						Type:      pkg.NpmPkg,
						Metadata: pkg.BunLockEntry{
							Integrity: "sha512-shared==",
						},
					},
				}
				rels := []artifact.Relationship{
					{From: pkgs[1], To: pkgs[0], Type: artifact.DependencyOfRelationship},
				}
				return pkgs, rels
			},
		},
		{
			name:       "include dev keeps everything including dev-only transitive",
			includeDev: true,
			expected: func(locations file.LocationSet) ([]pkg.Package, []artifact.Relationship) {
				pkgs := []pkg.Package{
					{
						Name:      "dev-only-transitive",
						Version:   "1.0.0",
						PURL:      "pkg:npm/dev-only-transitive@1.0.0",
						Locations: locations,
						Language:  pkg.JavaScript,
						Type:      pkg.NpmPkg,
						Metadata: pkg.BunLockEntry{
							Integrity: "sha512-devonly==",
						},
					},
					{
						Name:      "dev-pkg",
						Version:   "1.0.0",
						PURL:      "pkg:npm/dev-pkg@1.0.0",
						Locations: locations,
						Language:  pkg.JavaScript,
						Type:      pkg.NpmPkg,
						Metadata: pkg.BunLockEntry{
							Integrity: "sha512-dev==",
							Dependencies: map[string]string{
								"dev-only-transitive": "^1.0.0",
								"shared-pkg":          "^1.0.0",
							},
						},
					},
					{
						Name:      "prod-pkg",
						Version:   "1.0.0",
						PURL:      "pkg:npm/prod-pkg@1.0.0",
						Locations: locations,
						Language:  pkg.JavaScript,
						Type:      pkg.NpmPkg,
						Metadata: pkg.BunLockEntry{
							Integrity: "sha512-prod==",
							Dependencies: map[string]string{
								"shared-pkg": "^1.0.0",
							},
						},
					},
					{
						Name:      "shared-pkg",
						Version:   "1.0.0",
						PURL:      "pkg:npm/shared-pkg@1.0.0",
						Locations: locations,
						Language:  pkg.JavaScript,
						Type:      pkg.NpmPkg,
						Metadata: pkg.BunLockEntry{
							Integrity: "sha512-shared==",
						},
					},
				}
				rels := []artifact.Relationship{
					{From: pkgs[0], To: pkgs[1], Type: artifact.DependencyOfRelationship}, // dev-only-transitive -> dev-pkg
					{From: pkgs[3], To: pkgs[1], Type: artifact.DependencyOfRelationship}, // shared-pkg -> dev-pkg
					{From: pkgs[3], To: pkgs[2], Type: artifact.DependencyOfRelationship}, // shared-pkg -> prod-pkg
				}
				return pkgs, rels
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := "testdata/bun-lock/dev-deps/bun.lock"
			locations := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
			expectedPkgs, expectedRels := tt.expected(locations)

			adapter := newGenericBunLockAdapter(CatalogerConfig{IncludeDevDependencies: tt.includeDev})
			pkgtest.NewCatalogTester().
				FromDirectory(t, "testdata/bun-lock/dev-deps").
				FromFile(t, fixture).
				Expects(expectedPkgs, expectedRels).
				TestParser(t, adapter.parseBunLock)
		})
	}
}

func TestParseBunLock_JSONCFeatures(t *testing.T) {
	fixture := "testdata/bun-lock/jsonc-features/bun.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expectedPkgs := []pkg.Package{
		{
			Name:      "foo",
			Version:   "1.0.0",
			PURL:      "pkg:npm/foo@1.0.0",
			Locations: locations,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.BunLockEntry{
				Integrity: "sha512-foo==",
			},
		},
	}

	adapter := newGenericBunLockAdapter(CatalogerConfig{})
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/bun-lock/jsonc-features").
		FromFile(t, fixture).
		Expects(expectedPkgs, nil).
		TestParser(t, adapter.parseBunLock)
}

func TestSplitBunNameVersion(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		version string
	}{
		{"cowsay@1.6.0", "cowsay", "1.6.0"},
		{"@types/node@20.19.39", "@types/node", "20.19.39"},
		{"@scope/pkg-name@2.0.0-beta.1", "@scope/pkg-name", "2.0.0-beta.1"},
		{"name-without-version", "name-without-version", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			n, v := splitBunNameVersion(tt.input)
			assert.Equal(t, tt.name, n)
			assert.Equal(t, tt.version, v)
		})
	}
}

func TestStripJSONCExtras(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{
			name: "trailing comma in object",
			in:   `{"a": 1,}`,
			out:  `{"a": 1}`,
		},
		{
			name: "trailing comma in array",
			in:   `[1, 2, 3,]`,
			out:  `[1, 2, 3]`,
		},
		{
			name: "line comment stripped",
			in:   "{ // comment\n\"a\":1}",
			out:  "{ \n\"a\":1}",
		},
		{
			name: "block comment stripped",
			in:   `{ /* hi */ "a":1}`,
			out:  `{  "a":1}`,
		},
		{
			name: "multiline block comment stripped",
			in:   "{ /* line1\nline2\n*/ \"a\":1}",
			out:  "{  \"a\":1}",
		},
		{
			name: "comment-like content inside string is preserved",
			in:   `{"url": "https://example.com/path,", "other": 1}`,
			out:  `{"url": "https://example.com/path,", "other": 1}`,
		},
		{
			name: "trailing comma followed by whitespace then brace",
			in:   "{\"a\": 1,\n  }",
			out:  "{\"a\": 1\n  }",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(stripJSONCExtras([]byte(tt.in)))
			assert.Equal(t, tt.out, got)
		})
	}
}
