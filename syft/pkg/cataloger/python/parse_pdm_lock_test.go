package python

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePdmLock(t *testing.T) {

	fixture := "test-fixtures/pdm-lock/pdm.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "certifi",
			Version:   "2025.1.31",
			PURL:      "pkg:pypi/certifi@2025.1.31",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "Python package for providing Mozilla's CA Bundle.",
				Marker:  `python_version >= "3.6"`,
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "3d5da6925056f6f18f119200434a4780a94263f10d1c21d032a6f6b2baa20651",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "ca78db4565a652026a4db2bcdf68f2fb589ea80d0be70e03929ed730746b84fe",
						},
					},
				},
				RequiresPython: ">=3.6",
			},
		},
		{
			Name:      "chardet",
			Version:   "3.0.4",
			PURL:      "pkg:pypi/chardet@3.0.4",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "Universal encoding detector for Python 2 and 3",
				Marker:  `os_name == "nt"`,
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "fc323ffcaeaed0e0a02bf4d117757b98aed530d9ed4531e3e15460124c106691",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "84ab92ed1c4d4f16916e05906b6b75a6c0fb5db821cc65e70cbd64a3e2a5eaae",
						},
					},
				},
			},
		},
		{
			Name:      "charset-normalizer",
			Version:   "2.0.12",
			PURL:      "pkg:pypi/charset-normalizer@2.0.12",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "The Real First Universal Charset Detector. Open, modern and actively maintained alternative to Chardet.",
				Marker:  `python_version >= "3.6"`,
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "6881edbebdb17b39b4eaaa821b438bf6eddffb4468cf344f09f89def34a8b1df",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "2857e29ff0d34db842cd7ca3230549d1a697f96ee6d3fb071cfa6c7393832597",
						},
					},
				},
				RequiresPython: ">=3.5.0",
			},
		},
		{
			Name:      "colorama",
			Version:   "0.3.9",
			PURL:      "pkg:pypi/colorama@0.3.9",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "Cross-platform colored terminal text.",
				Marker:  `sys_platform == "win32"`,
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "463f8483208e921368c9f306094eb6f725c6ca42b0f97e313cb5d5512459feda",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "48eb22f4f8461b1df5734a074b57042430fb06e1d61bd1e11b078c0fe6d7a1f1",
						},
					},
				},
			},
		},
		{
			Name:      "idna",
			Version:   "2.7",
			PURL:      "pkg:pypi/idna@2.7",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "Internationalized Domain Names in Applications (IDNA)",
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "156a6814fb5ac1fc6850fb002e0852d56c0c8d2531923a51032d1b70760e186e",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "684a38a6f903c1d71d6d5fac066b58d7768af4de2b832e426ec79c30daa94a16",
						},
					},
				},
			},
		},
		{
			Name:      "py",
			Version:   "1.4.34",
			PURL:      "pkg:pypi/py@1.4.34",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "library with cross-python path, ini-parsing, io, code, log facilities",
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "2ccb79b01769d99115aa600d7eed99f524bf752bba8f041dc1c184853514655a",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "0f2d585d22050e90c7d293b6451c83db097df77871974d90efd5a30dc12fcde3",
						},
					},
				},
			},
		},
		{
			Name:      "pytest",
			Version:   "3.2.5",
			PURL:      "pkg:pypi/pytest@3.2.5",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "pytest: simple powerful testing with Python",
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "6d5bd4f7113b444c55a3bbb5c738a3dd80d43563d063fc42dcb0aaefbdd78b81",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "241d7e7798d79192a123ceaf64c602b4d233eacf6d6e42ae27caa97f498b7dc6",
						},
					},
				},
				Dependencies: []string{
					`argparse; python_version == "2.6"`,
					`colorama; sys_platform == "win32"`,
					`ordereddict; python_version == "2.6"`,
					"py>=1.4.33",
					"setuptools",
				},
			},
		},
		{
			Name:      "requests",
			Version:   "2.27.1",
			PURL:      "pkg:pypi/requests@2.27.1",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "Python HTTP for Humans.",
				Marker:  `python_version >= "3.6"`,
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "f22fa1e554c9ddfd16e6e41ac79759e17be9e492b3587efa038054674760e72d",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "68d7c56fd5a8999887728ef304a6d12edc7be74f1cfa47714fc8b414525c9a61",
						},
					},
				},
				RequiresPython: ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*",
				Dependencies: []string{
					"certifi>=2017.4.17",
					`chardet<5,>=3.0.2; python_version < "3"`,
					`charset-normalizer~=2.0.0; python_version >= "3"`,
					`idna<3,>=2.5; python_version < "3"`,
					`idna<4,>=2.5; python_version >= "3"`,
					"urllib3<1.27,>=1.21.1",
				},
			},
		},
		{
			Name:      "setuptools",
			Version:   "39.2.0",
			PURL:      "pkg:pypi/setuptools@39.2.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "Easily download, build, install, upgrade, and uninstall Python packages",
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "f7cddbb5f5c640311eb00eab6e849f7701fa70bf6a183fc8a2c33dd1d1672fb2",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "8fca9275c89964f13da985c3656cb00ba029d7f3916b37990927ffdf264e7926",
						},
					},
				},
				RequiresPython: ">=2.7,!=3.0.*,!=3.1.*,!=3.2.*",
			},
		},
		{
			Name:      "urllib3",
			Version:   "1.26.20",
			PURL:      "pkg:pypi/urllib3@1.26.20",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonPdmLockEntry{
				Summary: "HTTP library with thread-safe connection pooling, file post, and more.",
				Marker:  `python_version >= "3.6"`,
				Files: []pkg.PythonPdmFileEntry{
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "0ed14ccfbf1c30a9072c7ca157e4319b70d65f623e91e7b32fadb2853431016e",
						},
					},
					{
						URL: "",
						Digest: pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "40c2dc0c681e47eb8f90e7e27bf6ff7df2e677421fd46756da1161c39ca70d32",
						},
					},
				},
				RequiresPython: "!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*,!=3.5.*,>=2.7",
			},
		},
	}

	// Create a map for easy lookup of packages by name
	pkgMap := make(map[string]pkg.Package)
	for _, p := range expectedPkgs {
		pkgMap[p.Name] = p
	}

	expectedRelationships := []artifact.Relationship{
		// pytest dependencies
		{
			From: pkgMap["colorama"],
			To:   pkgMap["pytest"],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: pkgMap["py"],
			To:   pkgMap["pytest"],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: pkgMap["setuptools"],
			To:   pkgMap["pytest"],
			Type: artifact.DependencyOfRelationship,
		},
		// requests dependencies
		{
			From: pkgMap["certifi"],
			To:   pkgMap["requests"],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: pkgMap["chardet"],
			To:   pkgMap["requests"],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: pkgMap["charset-normalizer"],
			To:   pkgMap["requests"],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: pkgMap["urllib3"],
			To:   pkgMap["requests"],
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: pkgMap["idna"],
			To:   pkgMap["requests"],
			Type: artifact.DependencyOfRelationship,
		},
	}

	pdmLockParser := newPdmLockParser(DefaultCatalogerConfig())
	pkgtest.TestFileParser(t, fixture, pdmLockParser.parsePdmLock, expectedPkgs, expectedRelationships)
}

func TestParsePdmLockWithLicenseEnrichment(t *testing.T) {
	ctx := context.TODO()
	fixture := "test-fixtures/pypi-remote/pdm.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	mux, url, teardown := setupPypiRegistry()
	defer teardown()
	tests := []struct {
		name             string
		fixture          string
		config           CatalogerConfig
		requestHandlers  []handlerPath
		expectedPackages []pkg.Package
	}{
		{
			name:   "search remote licenses returns the expected licenses when search is set to true",
			config: CatalogerConfig{SearchRemoteLicenses: true},
			requestHandlers: []handlerPath{
				{
					path:    "/certifi/2025.10.5/json",
					handler: generateMockPypiRegistryHandler("test-fixtures/pypi-remote/registry_response.json"),
				},
			},
			expectedPackages: []pkg.Package{
				{
					Name:      "certifi",
					Version:   "2025.10.5",
					Locations: locations,
					PURL:      "pkg:pypi/certifi@2025.10.5",
					Licenses:  pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, "MPL-2.0")),
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonPdmLockEntry{
						Summary: "Python package for providing Mozilla's CA Bundle.",
						Marker:  `python_version >= "3.7"`,
						Files: []pkg.PythonPdmFileEntry{
							{
								URL: "",
								Digest: pkg.PythonFileDigest{
									Algorithm: "sha256",
									Value:     "47c09d31ccf2acf0be3f701ea53595ee7e0b8fa08801c6624be771df09ae7b43",
								},
							},
							{
								URL: "",
								Digest: pkg.PythonFileDigest{
									Algorithm: "sha256",
									Value:     "0f212c2744a9bb6de0c56639a6f68afe01ecd92d91f14ae897c4fe7bbeeef0de",
								},
							},
						},
						RequiresPython: ">=3.7",
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// set up the mock server
			for _, handler := range tc.requestHandlers {
				mux.HandleFunc(handler.path, handler.handler)
			}
			tc.config.PypiBaseURL = url
			pdmLockParser := newPdmLockParser(tc.config)
			pkgtest.TestFileParser(t, fixture, pdmLockParser.parsePdmLock, tc.expectedPackages, nil)
		})
	}
}

func TestParsePdmLockWithExtras(t *testing.T) {
	// This test verifies that PDM's multiple package entries for different extras combinations
	// are correctly merged into a single package node in the SBOM.
	//
	// The fixture contains TWO [[package]] entries for "coverage":
	//   1. Base coverage package (no extras)
	//   2. coverage with extras = ["toml"]
	//
	// We should get exactly ONE coverage package in the output, with extras properly tracked.

	fixture := "test-fixtures/pdm-lock-extras/pdm.lock"
	pdmLockParser := newPdmLockParser(DefaultCatalogerConfig())

	fh, err := os.Open(fixture)
	require.NoError(t, err)
	defer fh.Close()

	pkgs, relationships, err := pdmLockParser.parsePdmLock(
		context.TODO(),
		nil,
		nil,
		file.NewLocationReadCloser(file.NewLocation(fixture), fh),
	)

	require.NoError(t, err)

	// Verify we have the expected number of packages (NOT duplicated coverage)
	require.Len(t, pkgs, 5, "should have exactly 5 packages: coverage, pytest, pytest-cov, tomli, uvloop")

	// Find the coverage package and verify it's only present once
	var coveragePkg *pkg.Package
	coverageCount := 0
	for i := range pkgs {
		if pkgs[i].Name == "coverage" {
			coverageCount++
			coveragePkg = &pkgs[i]
		}
	}

	require.Equal(t, 1, coverageCount, "coverage should appear exactly ONCE in the package list (PDM has it twice in the lock file)")
	require.NotNil(t, coveragePkg, "coverage package should be found")

	// This test verifies file deduplication behavior!
	// The fixture has identical files in both base and extras=["toml"] entries.
	// After merging, the base should have Files populated, but the extras variant should NOT
	// have Files (they're deduplicated because they're identical to base).
	coverageMeta, ok := coveragePkg.Metadata.(pkg.PythonPdmLockEntry)
	require.True(t, ok, "coverage metadata should be PythonPdmLockEntry")

	expectedMeta := pkg.PythonPdmLockEntry{
		Summary:        "Code coverage measurement for Python",
		RequiresPython: ">=3.8",
		Files: []pkg.PythonPdmFileEntry{
			{
				URL: "coverage-7.4.1-cp310-cp310-macosx_10_9_x86_64.whl",
				Digest: pkg.PythonFileDigest{
					Algorithm: "sha256",
					Value:     "077d366e724f24fc02dbfe9d946534357fda71af9764ff99d73c3c596001bbd7",
				},
			},
			{
				URL: "coverage-7.4.1.tar.gz",
				Digest: pkg.PythonFileDigest{
					Algorithm: "sha256",
					Value:     "1ed4b95480952b1a26d863e546fa5094564aa0065e1e5f0d4d0041f293251d04",
				},
			},
		},
		Extras: []pkg.PythonPdmLockExtraVariant{
			{
				Extras: []string{"toml"},
				Dependencies: []string{
					"coverage==7.4.1",
					"tomli; python_full_version <= \"3.11.0a6\"",
				},
				// Files is nil/empty here because they're identical to base (deduplicated)
			},
		},
	}

	if diff := cmp.Diff(expectedMeta, coverageMeta); diff != "" {
		t.Errorf("coverage metadata mismatch (-want +got):\n%s", diff)
	}

	// Verify relationships were created
	require.NotEmpty(t, relationships, "relationships should be created")

	// Verify pytest-cov has a relationship to coverage
	// Build a package map for easy lookup
	pkgMap := make(map[string]pkg.Package)
	for _, p := range pkgs {
		pkgMap[p.Name] = p
	}

	// Verify tomli package has marker preserved
	var tomliPkg *pkg.Package
	for i := range pkgs {
		if pkgs[i].Name == "tomli" {
			tomliPkg = &pkgs[i]
			break
		}
	}
	require.NotNil(t, tomliPkg, "tomli package should be found")
	tomliMeta, ok := tomliPkg.Metadata.(pkg.PythonPdmLockEntry)
	require.True(t, ok, "tomli metadata should be PythonPdmLockEntry")
	require.Equal(t, `python_version < "3.11"`, tomliMeta.Marker, "tomli should have marker preserved")

	// Verify uvloop package has complex marker preserved (multiple AND conditions, negations, mixed quotes)
	var uvloopPkg *pkg.Package
	for i := range pkgs {
		if pkgs[i].Name == "uvloop" {
			uvloopPkg = &pkgs[i]
			break
		}
	}
	require.NotNil(t, uvloopPkg, "uvloop package should be found")
	uvloopMeta, ok := uvloopPkg.Metadata.(pkg.PythonPdmLockEntry)
	require.True(t, ok, "uvloop metadata should be PythonPdmLockEntry")
	require.Equal(t, `platform_python_implementation != 'PyPy' and sys_platform != 'win32' and python_version >= "3.8"`, uvloopMeta.Marker, "uvloop should have complex marker preserved exactly as-is")

	var foundPytestCovToCoverage bool
	for _, rel := range relationships {
		toPkg, toOk := rel.To.(pkg.Package)
		fromPkg, fromOk := rel.From.(pkg.Package)
		if toOk && fromOk && toPkg.Name == "pytest-cov" && fromPkg.Name == "coverage" {
			foundPytestCovToCoverage = true
			break
		}
	}
	require.True(t, foundPytestCovToCoverage, "should have a dependency relationship from coverage to pytest-cov")
}

func TestParsePdmLockWithSeparateFilesFixture(t *testing.T) {
	// verify that PythonPdmLockExtraVariant metadata is properly populated when parsing PDM lock files
	// with extras variants. The separate-files fixture contains rfc3986 with base + extras=["idna2008"] variant.
	//
	// The fixture contains TWO [[package]] entries for "rfc3986":
	//   1. Base rfc3986 package (no extras, no dependencies)
	//   2. rfc3986 with extras = ["idna2008"] and dependencies = ["idna", "rfc3986==1.5.0"]
	//
	// We should get exactly ONE rfc3986 package in the output, with the extras variant properly tracked
	// in the Extras field.

	fixture := "test-fixtures/pdm-lock-separate-files/pdm.lock"
	pdmLockParser := newPdmLockParser(DefaultCatalogerConfig())

	fh, err := os.Open(fixture)
	require.NoError(t, err)
	defer fh.Close()

	pkgs, relationships, err := pdmLockParser.parsePdmLock(
		context.TODO(),
		nil,
		nil,
		file.NewLocationReadCloser(file.NewLocation(fixture), fh),
	)

	require.NoError(t, err)

	// Find the rfc3986 package and verify it's only present once
	var rfc3986Pkg *pkg.Package
	rfc3986Count := 0
	for i := range pkgs {
		if pkgs[i].Name == "rfc3986" {
			rfc3986Count++
			rfc3986Pkg = &pkgs[i]
		}
	}

	require.Equal(t, 1, rfc3986Count)
	require.NotNil(t, rfc3986Pkg)

	require.Equal(t, "rfc3986", rfc3986Pkg.Name)
	require.Equal(t, "1.5.0", rfc3986Pkg.Version)

	rfc3986Meta, ok := rfc3986Pkg.Metadata.(pkg.PythonPdmLockEntry)
	require.True(t, ok)

	expectedMeta := pkg.PythonPdmLockEntry{
		Summary:        "Validating URI References per RFC 3986",
		RequiresPython: "",
		Files:          nil, // base package has no files in fixture
		Extras: []pkg.PythonPdmLockExtraVariant{
			{
				Extras: []string{"idna2008"},
				Dependencies: []string{
					"idna",
					"rfc3986==1.5.0",
				},
				Files: nil, // variant also has no files (fixture has no files for either entry)
			},
		},
	}

	if diff := cmp.Diff(expectedMeta, rfc3986Meta); diff != "" {
		t.Errorf("rfc3986 metadata mismatch (-want +got):\n%s", diff)
	}

	require.NotEmpty(t, relationships, "relationships should be created")
}

func TestMergePdmLockPackagesNoBasePackage(t *testing.T) {
	// test the edge case where only extras variants exist (no base package entry)
	// this can happen if PDM lock file only contains package entries with extras
	packages := []pdmLockPackage{
		{
			Name:           "test-package",
			Version:        "1.0.0",
			RequiresPython: ">=3.8",
			Summary:        "Test package summary",
			Marker:         "extra == 'dev'",
			Dependencies:   []string{"pytest", "test-package==1.0.0"},
			Extras:         []string{"dev"},
			Files: []pdmLockPackageFile{
				{
					File: "test-package-1.0.0.tar.gz",
					Hash: "sha256:abc123",
				},
			},
		},
		{
			Name:           "test-package",
			Version:        "1.0.0",
			RequiresPython: ">=3.8",
			Summary:        "Test package summary",
			Marker:         "extra == 'test'",
			Dependencies:   []string{"coverage", "test-package==1.0.0"},
			Extras:         []string{"test"},
			Files: []pdmLockPackageFile{
				{
					File: "test-package-1.0.0.tar.gz",
					Hash: "sha256:abc123",
				},
			},
		},
	}

	entry := mergePdmLockPackages(packages)

	// verify fallback logic: when no base package exists, first package's metadata is used
	require.Equal(t, "Test package summary", entry.Summary)
	require.Equal(t, ">=3.8", entry.RequiresPython)
	require.Equal(t, []string{"pytest", "test-package==1.0.0"}, entry.Dependencies)
	require.Equal(t, "extra == 'dev'", entry.Marker)

	// verify both extras variants are present
	require.Len(t, entry.Extras, 2)
	require.Equal(t, []string{"dev"}, entry.Extras[0].Extras)
	require.Equal(t, []string{"pytest", "test-package==1.0.0"}, entry.Extras[0].Dependencies)
	require.Equal(t, []string{"test"}, entry.Extras[1].Extras)
	require.Equal(t, []string{"coverage", "test-package==1.0.0"}, entry.Extras[1].Dependencies)
}

func Test_corruptPdmLock(t *testing.T) {
	psr := newPdmLockParser(DefaultCatalogerConfig())
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/pdm.lock").
		WithError().
		TestParser(t, psr.parsePdmLock)
}
