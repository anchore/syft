package python

import (
	"context"
	"testing"

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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "3d5da6925056f6f18f119200434a4780a94263f10d1c21d032a6f6b2baa20651",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "ca78db4565a652026a4db2bcdf68f2fb589ea80d0be70e03929ed730746b84fe",
						},
					},
				},
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "fc323ffcaeaed0e0a02bf4d117757b98aed530d9ed4531e3e15460124c106691",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "6881edbebdb17b39b4eaaa821b438bf6eddffb4468cf344f09f89def34a8b1df",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "2857e29ff0d34db842cd7ca3230549d1a697f96ee6d3fb071cfa6c7393832597",
						},
					},
				},
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "463f8483208e921368c9f306094eb6f725c6ca42b0f97e313cb5d5512459feda",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "156a6814fb5ac1fc6850fb002e0852d56c0c8d2531923a51032d1b70760e186e",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "2ccb79b01769d99115aa600d7eed99f524bf752bba8f041dc1c184853514655a",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "6d5bd4f7113b444c55a3bbb5c738a3dd80d43563d063fc42dcb0aaefbdd78b81",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "241d7e7798d79192a123ceaf64c602b4d233eacf6d6e42ae27caa97f498b7dc6",
						},
					},
				},
				Dependencies: []string{
					"argparse",
					"colorama",
					"ordereddict",
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "f22fa1e554c9ddfd16e6e41ac79759e17be9e492b3587efa038054674760e72d",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "68d7c56fd5a8999887728ef304a6d12edc7be74f1cfa47714fc8b414525c9a61",
						},
					},
				},
				Dependencies: []string{
					"certifi>=2017.4.17",
					"chardet<5,>=3.0.2",
					"charset-normalizer~=2.0.0",
					"idna<3,>=2.5",
					"idna<4,>=2.5",
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "f7cddbb5f5c640311eb00eab6e849f7701fa70bf6a183fc8a2c33dd1d1672fb2",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "8fca9275c89964f13da985c3656cb00ba029d7f3916b37990927ffdf264e7926",
						},
					},
				},
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
				Files: []pkg.PythonFileRecord{
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "0ed14ccfbf1c30a9072c7ca157e4319b70d65f623e91e7b32fadb2853431016e",
						},
					},
					{
						Path: "",
						Digest: &pkg.PythonFileDigest{
							Algorithm: "sha256",
							Value:     "40c2dc0c681e47eb8f90e7e27bf6ff7df2e677421fd46756da1161c39ca70d32",
						},
					},
				},
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
						Files: []pkg.PythonFileRecord{
							{
								Path: "",
								Digest: &pkg.PythonFileDigest{
									Algorithm: "sha256",
									Value:     "47c09d31ccf2acf0be3f701ea53595ee7e0b8fa08801c6624be771df09ae7b43",
								},
							},
							{
								Path: "",
								Digest: &pkg.PythonFileDigest{
									Algorithm: "sha256",
									Value:     "0f212c2744a9bb6de0c56639a6f68afe01ecd92d91f14ae897c4fe7bbeeef0de",
								},
							},
						},
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

func Test_corruptPdmLock(t *testing.T) {
	pdmLockParser := newPdmLockParser(DefaultCatalogerConfig())
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/pdm.lock").
		WithError().
		TestParser(t, pdmLockParser.parsePdmLock)
}
