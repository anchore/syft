package bitnami

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func mustCPEs(s ...string) (c []cpe.CPE) {
	for _, i := range s {
		newCPE := cpe.Must(i, "")
		newCPE.Source = cpe.DeclaredSource
		c = append(c, newCPE)
	}
	return
}

func TestBitnamiCataloger(t *testing.T) {
	apacheMainPkg := pkg.Package{
		Name:      "apache",
		Version:   "2.4.62-3",
		Type:      pkg.BitnamiPkg,
		Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/apache/.spdx-apache.spdx")),
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromType("Apache-2.0", license.Concluded),
			pkg.NewLicenseFromType("Apache-2.0", license.Declared),
		),
		FoundBy: catalogerName,
		PURL:    "pkg:bitnami/apache@2.4.62-3?arch=arm64&distro=debian-12",
		CPEs: mustCPEs(
			"cpe:2.3:*:apache:http_server:2.4.62:*:*:*:*:*:*:*",
		),
		Metadata: &pkg.BitnamiEntry{
			Name:         "apache",
			Version:      "2.4.62",
			Revision:     "3",
			Architecture: "arm64",
			Distro:       "debian-12",
		},
	}
	apacheSecondaryPkgs := []pkg.Package{
		{
			Name:      "apr",
			Version:   "1.7.5",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/apache/.spdx-apache.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromType("Apache-2.0", license.Concluded),
				pkg.NewLicenseFromType("Apache-2.0", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/apr@1.7.5?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:apache:portable_runtime:1.7.5:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiEntry{
				Name:         "apr",
				Version:      "1.7.5",
				Architecture: "arm64",
				Distro:       "debian-12",
			},
		},
		{
			Name:      "apr-util",
			Version:   "1.6.3",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/apache/.spdx-apache.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromType("Apache-2.0", license.Concluded),
				pkg.NewLicenseFromType("Apache-2.0", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/apr-util@1.6.3?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:apache:apr-util:1.6.3:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiEntry{
				Name:         "apr-util",
				Version:      "1.6.3",
				Architecture: "arm64",
				Distro:       "debian-12",
			},
		},
		{
			Name:      "modsecurity2",
			Version:   "2.9.7",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/apache/.spdx-apache.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromType("Apache-2.0", license.Concluded),
				pkg.NewLicenseFromType("Apache-2.0", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/modsecurity2@2.9.7?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:trustwave:modsecurity:2.9.7:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiEntry{
				Name:         "modsecurity2",
				Version:      "2.9.7",
				Architecture: "arm64",
				Distro:       "debian-12",
			},
		},
		{
			Name:      "modsecurity",
			Version:   "3.0.13",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/apache/.spdx-apache.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromType("Apache-2.0", license.Concluded),
				pkg.NewLicenseFromType("Apache-2.0", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/modsecurity@3.0.13?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:trustwave:modsecurity:3.0.13:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiEntry{
				Name:         "modsecurity",
				Version:      "3.0.13",
				Architecture: "arm64",
				Distro:       "debian-12",
			},
		},
		{
			Name:      "modsecurity-apache",
			Version:   "0.20210819.0",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/apache/.spdx-apache.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromType("Apache-2.0", license.Concluded),
				pkg.NewLicenseFromType("Apache-2.0", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/modsecurity-apache@0.20210819.0?arch=arm64&distro=debian-12",
			Metadata: &pkg.BitnamiEntry{
				Name:         "modsecurity-apache",
				Version:      "0.20210819.0",
				Architecture: "arm64",
				Distro:       "debian-12",
			},
		},
	}

	apacheExpectedPkgs := []pkg.Package{apacheMainPkg}
	apacheExpectedPkgs = append(apacheExpectedPkgs, apacheSecondaryPkgs...)
	//sort.Sort(apacheExpectedPkgs)
	var apacheExpectedRelationships []artifact.Relationship
	for _, p := range apacheSecondaryPkgs {
		apacheExpectedRelationships = append(apacheExpectedRelationships, artifact.Relationship{
			From: apacheMainPkg,
			To:   p,
			Type: artifact.ContainsRelationship,
		})
	}

	renderTemplateMainPkg := pkg.Package{
		Name:      "render-template",
		Version:   "1.0.7-4",
		Type:      pkg.BitnamiPkg,
		Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/render-template/.spdx-render-template.spdx")),
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromType("Apache-2.0", license.Concluded),
			pkg.NewLicenseFromType("Apache-2.0", license.Declared),
		),
		FoundBy: catalogerName,
		PURL:    "pkg:bitnami/render-template@1.0.7-4?arch=arm64&distro=debian-12",
		CPEs: mustCPEs(
			"cpe:2.3:*:render-template:render-template:1.0.7:*:*:*:*:*:*:*",
		),
		Metadata: &pkg.BitnamiEntry{
			Name:         "render-template",
			Version:      "1.0.7",
			Revision:     "4",
			Architecture: "arm64",
			Distro:       "debian-12",
		},
	}

	tests := []struct {
		name              string
		fixture           string
		wantPkgs          []pkg.Package
		wantRelationships []artifact.Relationship
		wantErr           require.ErrorAssertionFunc
	}{
		{
			name:              "parse valid Apache SBOM",
			fixture:           "test-fixtures/json",
			wantPkgs:          apacheExpectedPkgs,
			wantRelationships: apacheExpectedRelationships,
			wantErr:           require.NoError,
		},
		{
			name:              "parse valid SBOM that includes both Bitnami and non-Bitnami packages",
			fixture:           "test-fixtures/mix",
			wantPkgs:          []pkg.Package{renderTemplateMainPkg},
			wantRelationships: nil,
			wantErr:           require.NoError,
		},
		{
			name:              "Redis SBOM with not allowed tag-value format",
			fixture:           "test-fixtures/tag-value",
			wantPkgs:          nil,
			wantRelationships: nil,
			wantErr:           require.NoError,
		},
		{
			name:              "Invalid Apache SBOM",
			fixture:           "test-fixtures/invalid",
			wantPkgs:          nil,
			wantRelationships: nil,
			wantErr:           require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixture).
				Expects(tt.wantPkgs, tt.wantRelationships).
				WithErrorAssertion(tt.wantErr).
				TestCataloger(t, NewCataloger())
		})
	}
}
