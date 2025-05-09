package gentoo

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestPortageCataloger(t *testing.T) {
	tests := []struct {
		name                  string
		fixture               string
		expectedPackages      []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			name:    "standard skopeo package",
			fixture: "test-fixtures/layout",
			expectedPackages: []pkg.Package{
				{
					Name:    "app-containers/skopeo",
					Version: "1.5.1",
					FoundBy: "portage-cataloger",
					PURL:    "pkg:ebuild/app-containers%2Fskopeo@1.5.1",
					Locations: file.NewLocationSet(
						file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/CONTENTS"),
						file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/SIZE"),
						file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/LICENSE"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicensesFromLocation(
							file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/LICENSE"),
							"Apache-2.0 AND BSD AND BSD-2 AND CC-BY-SA-4.0 AND ISC AND MIT")...,
					),
					Type: pkg.PortagePkg,
					Metadata: pkg.PortageEntry{
						InstalledSize: 27937835,
						Licenses:      "Apache-2.0 BSD BSD-2 CC-BY-SA-4.0 ISC MIT",
						Files: []pkg.PortageFileRecord{
							{
								Path: "/usr/bin/skopeo",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "376c02bd3b22804df8fdfdc895e7dbfb",
								},
							},
							{
								Path: "/etc/containers/policy.json",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "c01eb6950f03419e09d4fc88cb42ff6f",
								},
							},
							{
								Path: "/etc/containers/registries.d/default.yaml",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "e6e66cd3c24623e0667f26542e0e08f6",
								},
							},
							{
								Path: "/var/lib/atomic/sigstore/.keep_app-containers_skopeo-0",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "d41d8cd98f00b204e9800998ecf8427e",
								},
							},
						},
					},
				},
			},
			// not supported at this time
			expectedRelationships: nil,
		},
		{
			name:    "standard skopeo package with license groups",
			fixture: "test-fixtures/layout-license-groups",
			expectedPackages: []pkg.Package{
				{
					Name:    "app-containers/skopeo",
					Version: "1.5.1",
					FoundBy: "portage-cataloger",
					PURL:    "pkg:ebuild/app-containers%2Fskopeo@1.5.1",
					Locations: file.NewLocationSet(
						file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/CONTENTS"),
						file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/SIZE"),
						file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/LICENSE"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.NewLicensesFromLocation(
							file.NewLocation("var/db/pkg/app-containers/skopeo-1.5.1/LICENSE"),
							"Apache-2.0 AND BSD AND BSD-2 AND CC-BY-SA-4.0 AND ISC AND MIT")...,
					),
					Type: pkg.PortagePkg,
					Metadata: pkg.PortageEntry{
						InstalledSize: 27937835,
						Licenses:      "@GROUP1 @MIT-LIKE",
						Files: []pkg.PortageFileRecord{
							{
								Path: "/usr/bin/skopeo",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "376c02bd3b22804df8fdfdc895e7dbfb",
								},
							},
							{
								Path: "/etc/containers/policy.json",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "c01eb6950f03419e09d4fc88cb42ff6f",
								},
							},
							{
								Path: "/etc/containers/registries.d/default.yaml",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "e6e66cd3c24623e0667f26542e0e08f6",
								},
							},
							{
								Path: "/var/lib/atomic/sigstore/.keep_app-containers_skopeo-0",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "d41d8cd98f00b204e9800998ecf8427e",
								},
							},
						},
					},
				},
			},
			// not supported at this time
			expectedRelationships: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				Expects(test.expectedPackages, test.expectedRelationships).
				TestCataloger(t, NewPortageCataloger())
		})
	}
}

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain portage contents file",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"var/db/pkg/x/y/CONTENTS",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPortageCataloger())
		})
	}
}
