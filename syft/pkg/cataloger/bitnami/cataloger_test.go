package bitnami

import (
	"context"
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
	ctx := context.TODO()
	postgresqlMainPkg := pkg.Package{
		Name:      "postgresql",
		Version:   "17.2.0-8",
		Type:      pkg.BitnamiPkg,
		Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromTypeWithContext(ctx, "PostgreSQL", license.Concluded),
			pkg.NewLicenseFromTypeWithContext(ctx, "PostgreSQL", license.Declared),
		),
		FoundBy: catalogerName,
		PURL:    "pkg:bitnami/postgresql@17.2.0-8?arch=arm64&distro=debian-12",
		CPEs: mustCPEs(
			"cpe:2.3:*:postgresql:postgresql:17.2.0:*:*:*:*:*:*:*",
		),
		Metadata: &pkg.BitnamiSBOMEntry{
			Name:         "postgresql",
			Version:      "17.2.0",
			Revision:     "8",
			Architecture: "arm64",
			Distro:       "debian-12",
			Path:         "opt/bitnami/postgresql",
			Files: []string{
				"opt/bitnami/postgresql/readme.txt",
			},
		},
	}
	postgresqlSecondaryPkgs := []pkg.Package{
		{
			Name:      "geos",
			Version:   "3.13.0",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "LGPL-2.1-only", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "LGPL-2.1-only", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/geos@3.13.0?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:libgeos:geos:3.13.0:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "geos",
				Version:      "3.13.0",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "proj",
			Version:   "6.3.2",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/proj@6.3.2?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:proj:proj:6.3.2:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "proj",
				Version:      "6.3.2",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "gdal",
			Version:   "3.10.1",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/gdal@3.10.1?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:osgeo:gdal:3.10.1:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "gdal",
				Version:      "3.10.1",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "json-c",
			Version:   "0.16.20220414",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/json-c@0.16.20220414?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:json-c_project:json-c:0.16.20220414:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "json-c",
				Version:      "0.16.20220414",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "orafce",
			Version:   "4.14.1",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "0BSD", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "0BSD", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/orafce@4.14.1?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:orafce:orafce:4.14.1:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "orafce",
				Version:      "4.14.1",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "pljava",
			Version:   "1.6.8",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/pljava@1.6.8?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:pl/java_project:pl/java:1.6.8:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "pljava",
				Version:      "1.6.8",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
				Files: []string{
					"opt/bitnami/postgresql/share/pljava/pljava-api-1.6.8.jar",
					"opt/bitnami/postgresql/share/pljava/pljava-1.6.8.jar",
					"opt/bitnami/postgresql/share/pljava/pljava-examples-1.6.8.jar",
				},
			},
		},
		{
			Name:      "unixodbc",
			Version:   "2.3.12",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "LGPL-2.1-only", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "LGPL-2.1-only", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/unixodbc@2.3.12?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:unixodbc:unixodbc:2.3.12:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "unixodbc",
				Version:      "2.3.12",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "psqlodbc",
			Version:   "16.0.0",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "LGPL-3.0-only", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "LGPL-3.0-only", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/psqlodbc@16.0.0?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:postgresql:psqlodbc:16.0.0:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "psqlodbc",
				Version:      "16.0.0",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "protobuf",
			Version:   "3.21.12",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/protobuf@3.21.12?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:golang:protobuf:3.21.12:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "protobuf",
				Version:      "3.21.12",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "protobuf-c",
			Version:   "1.5.1",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-2-Clause", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-2-Clause", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/protobuf-c@1.5.1?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:protobuf-c:protobuf-c:1.5.1:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "protobuf-c",
				Version:      "1.5.1",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "postgis",
			Version:   "3.4.4",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "GPL-2.0-or-later", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "GPL-2.0-or-later", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/postgis@3.4.4?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:postgis:postgis:3.4.4:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "postgis",
				Version:      "3.4.4",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "pgaudit",
			Version:   "17.0.0",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "PostgreSQL", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "PostgreSQL", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/pgaudit@17.0.0?arch=arm64&distro=debian-12",
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "pgaudit",
				Version:      "17.0.0",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "pgbackrest",
			Version:   "2.54.2",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "MIT", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/pgbackrest@2.54.2?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:pgbackrest:pgbackrest:2.54.2:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "pgbackrest",
				Version:      "2.54.2",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "wal2json",
			Version:   "2.6.0",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/wal2json@2.6.0?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:wal2json:wal2json:2.6.0:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "wal2json",
				Version:      "2.6.0",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
		{
			Name:      "nss-wrapper",
			Version:   "1.1.16",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/postgresql/.spdx-postgresql.spdx")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Concluded),
				pkg.NewLicenseFromTypeWithContext(ctx, "BSD-3-Clause", license.Declared),
			),
			FoundBy: catalogerName,
			PURL:    "pkg:bitnami/nss_wrapper@1.1.16?arch=arm64&distro=debian-12",
			CPEs: mustCPEs(
				"cpe:2.3:*:nss_wrapper:nss_wrapper:1.1.16:*:*:*:*:*:*:*",
			),
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "nss_wrapper",
				Version:      "1.1.16",
				Architecture: "arm64",
				Distro:       "debian-12",
				Path:         "opt/bitnami/postgresql",
			},
		},
	}

	postgresqlExpectedPkgs := []pkg.Package{postgresqlMainPkg}
	postgresqlExpectedPkgs = append(postgresqlExpectedPkgs, postgresqlSecondaryPkgs...)
	pkg.Sort(postgresqlExpectedPkgs)
	var postgresqlExpectedRelationships []artifact.Relationship
	for _, p := range postgresqlSecondaryPkgs {
		postgresqlExpectedRelationships = append(postgresqlExpectedRelationships, artifact.Relationship{
			From: postgresqlMainPkg,
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
			pkg.NewLicenseFromTypeWithContext(ctx, "Apache-2.0", license.Concluded),
			pkg.NewLicenseFromTypeWithContext(ctx, "Apache-2.0", license.Declared),
		),
		FoundBy: catalogerName,
		PURL:    "pkg:bitnami/render-template@1.0.7-4?arch=arm64&distro=debian-12",
		CPEs: mustCPEs(
			"cpe:2.3:*:render-template:render-template:1.0.7:*:*:*:*:*:*:*",
		),
		Metadata: &pkg.BitnamiSBOMEntry{
			Name:         "render-template",
			Version:      "1.0.7",
			Revision:     "4",
			Architecture: "arm64",
			Distro:       "debian-12",
			Path:         "opt/bitnami/render-template",
			Files:        []string{},
		},
	}

	redisMainPkg := pkg.Package{
		Name:      "redis",
		Version:   "7.4.0-0",
		Type:      pkg.BitnamiPkg,
		Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/redis/.spdx-redis.spdx")),
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromTypeWithContext(ctx, "RSALv2", license.Concluded),
			pkg.NewLicenseFromTypeWithContext(ctx, "RSALv2", license.Declared),
		),
		FoundBy: catalogerName,
		PURL:    "pkg:bitnami/redis@7.4.0-0?arch=arm64&distro=debian-12",
		CPEs: mustCPEs(
			"cpe:2.3:*:redis:redis:7.4.0:*:*:*:*:*:*:*",
		),
		Metadata: &pkg.BitnamiSBOMEntry{
			Name:         "redis",
			Version:      "7.4.0",
			Revision:     "0",
			Architecture: "arm64",
			Distro:       "debian-12",
			Path:         "opt/bitnami/redis",
			Files:        []string{"opt/bitnami/redis/bin/redis-server"},
		},
	}

	mongodbComponentsPkgs := []pkg.Package{
		{
			Name:      "gosu",
			Version:   "1.14.0-1",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/.bitnami_components.json")),
			FoundBy:   catalogerName,
			PURL:      "pkg:bitnami/gosu@1.14.0-1?arch=amd64&distro=debian-10",
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "gosu",
				Version:      "1.14.0",
				Revision:     "1",
				Architecture: "amd64",
				Distro:       "debian-10",
				Path:         "opt/bitnami/gosu",
			},
		},
		{
			Name:      "mongodb",
			Version:   "4.4.11-2",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/.bitnami_components.json")),
			FoundBy:   catalogerName,
			PURL:      "pkg:bitnami/mongodb@4.4.11-2?arch=amd64&distro=debian-10",
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "mongodb",
				Version:      "4.4.11",
				Revision:     "2",
				Architecture: "amd64",
				Distro:       "debian-10",
				Path:         "opt/bitnami/mongodb",
			},
		},
		{
			Name:      "render-template",
			Version:   "1.0.1-5",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/.bitnami_components.json")),
			FoundBy:   catalogerName,
			PURL:      "pkg:bitnami/render-template@1.0.1-5?arch=amd64&distro=debian-10",
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "render-template",
				Version:      "1.0.1",
				Revision:     "5",
				Architecture: "amd64",
				Distro:       "debian-10",
				Path:         "opt/bitnami/render-template",
			},
		},
		{
			Name:      "wait-for-port",
			Version:   "1.0.1-5",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/.bitnami_components.json")),
			FoundBy:   catalogerName,
			PURL:      "pkg:bitnami/wait-for-port@1.0.1-5?arch=amd64&distro=debian-10",
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "wait-for-port",
				Version:      "1.0.1",
				Revision:     "5",
				Architecture: "amd64",
				Distro:       "debian-10",
				Path:         "opt/bitnami/wait-for-port",
			},
		},
		{
			Name:      "yq",
			Version:   "4.16.2-2",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/.bitnami_components.json")),
			FoundBy:   catalogerName,
			PURL:      "pkg:bitnami/yq@4.16.2-2?arch=amd64&distro=debian-10",
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "yq",
				Version:      "4.16.2",
				Revision:     "2",
				Architecture: "amd64",
				Distro:       "debian-10",
				Path:         "opt/bitnami/yq",
			},
		},
	}
	pkg.Sort(mongodbComponentsPkgs)

	postgresqlComponentsPkgs := []pkg.Package{
		{
			Name:      "postgresql",
			Version:   "11.22.0-4",
			Type:      pkg.BitnamiPkg,
			Locations: file.NewLocationSet(file.NewLocation("opt/bitnami/.bitnami_components.json")),
			FoundBy:   catalogerName,
			PURL:      "pkg:bitnami/postgresql@11.22.0-4?arch=amd64&distro=debian-11",
			Metadata: &pkg.BitnamiSBOMEntry{
				Name:         "postgresql",
				Version:      "11.22.0",
				Revision:     "4",
				Architecture: "amd64",
				Distro:       "debian-11",
				Path:         "opt/bitnami/postgresql",
			},
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
			name:              "parse valid PostgreSQL SBOM",
			fixture:           "test-fixtures/json",
			wantPkgs:          postgresqlExpectedPkgs,
			wantRelationships: postgresqlExpectedRelationships,
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
			name:              "Invalid SBOM",
			fixture:           "test-fixtures/invalid",
			wantPkgs:          nil,
			wantRelationships: nil,
			wantErr:           require.Error,
		},
		{
			name:              "SBOM with no relationships",
			fixture:           "test-fixtures/no-rel",
			wantPkgs:          []pkg.Package{redisMainPkg},
			wantRelationships: nil,
		},
		{
			name:              "parse legacy .bitnami_components.json (MongoDB with multiple components)",
			fixture:           "test-fixtures/components-json-mongodb",
			wantPkgs:          mongodbComponentsPkgs,
			wantRelationships: nil,
			wantErr:           require.NoError,
		},
		{
			name:              "parse legacy .bitnami_components.json (PostgreSQL single component, no digest)",
			fixture:           "test-fixtures/components-json-postgresql",
			wantPkgs:          postgresqlComponentsPkgs,
			wantRelationships: nil,
			wantErr:           require.NoError,
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
