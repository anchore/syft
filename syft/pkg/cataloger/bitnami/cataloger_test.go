package bitnami

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/stretchr/testify/require"
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
	var expectedPkgs = []pkg.Package{
		{
			Name:      "redis",
			Version:   "7.4.1-0",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/redis/.spdx-redis.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromType("RSALv2", license.Concluded),
				pkg.NewLicenseFromType("RSALv2", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/redis@7.4.1-0?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:redis:redis:7.4.1:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiEntry{
				Name:         "redis",
				Version:      "7.4.1",
				Revision:     "0",
				Architecture: "arm64",
				Distro:       "debian-12",
			},
		},
	}
	var expectedRelationships []artifact.Relationship
	for _, p := range expectedPkgs {
		expectedRelationships = append(expectedRelationships, artifact.Relationship{
			From: p,
			To: file.Coordinates{
				RealPath: "opt/bitnami/redis/.spdx-redis.spdx",
			},
			Type: artifact.DescribedByRelationship,
		})
	}

	tests := []struct {
		name              string
		fixture           string
		wantPkgs          []pkg.Package
		wantRelationships []artifact.Relationship
		wantErr           require.ErrorAssertionFunc
	}{
		{
			name:              "parse valid Redis SBOM",
			fixture:           "test-fixtures/json",
			wantPkgs:          expectedPkgs,
			wantRelationships: expectedRelationships,
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
			name:              "Invalid Redis SBOM",
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
