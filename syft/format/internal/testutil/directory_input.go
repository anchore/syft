package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source/directorysource"
)

func DirectoryInput(t testing.TB, dir string) sbom.SBOM {
	catalog := newDirectoryCatalog()

	path := filepath.Join(dir, "some", "path")

	require.NoError(t, os.MkdirAll(path, 0755))

	src, err := directorysource.New(
		directorysource.Config{
			Path: path,
			Base: dir,
		},
	)
	require.NoError(t, err)

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: catalog,
			LinuxDistribution: &linux.Release{
				PrettyName: "debian",
				Name:       "debian",
				ID:         "debian",
				IDLike:     []string{"like!"},
				Version:    "1.2.3",
				VersionID:  "1.2.3",
			},
		},
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
			// the application configuration should be persisted here, however, we do not want to import
			// the application configuration in this package (it's reserved only for ingestion by the cmd package)
			Configuration: map[string]string{
				"config-key": "config-value",
			},
		},
	}
}

func DirectoryInputWithAuthorField(t testing.TB) sbom.SBOM {
	catalog := newDirectoryCatalogWithAuthorField()

	dir := t.TempDir()
	path := filepath.Join(dir, "some", "path")

	require.NoError(t, os.MkdirAll(path, 0755))

	src, err := directorysource.New(
		directorysource.Config{
			Path: path,
			Base: dir,
		},
	)
	require.NoError(t, err)

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: catalog,
			LinuxDistribution: &linux.Release{
				PrettyName: "debian",
				Name:       "debian",
				ID:         "debian",
				IDLike:     []string{"like!"},
				Version:    "1.2.3",
				VersionID:  "1.2.3",
			},
		},
		Source: src.Describe(),
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
			// the application configuration should be persisted here, however, we do not want to import
			// the application configuration in this package (it's reserved only for ingestion by the cmd package)
			Configuration: map[string]string{
				"config-key": "config-value",
			},
		},
	}
}

func newDirectoryCatalog() *pkg.Collection {
	catalog := pkg.NewCollection()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.PythonPkg,
		FoundBy: "the-cataloger-1",
		Locations: file.NewLocationSet(
			file.NewLocation("/some/path/pkg1"),
		),
		Language: pkg.Python,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense("MIT"),
		),
		Metadata: pkg.PythonPackage{
			Name:    "package-1",
			Version: "1.0.1",
			Files: []pkg.PythonFileRecord{
				{
					Path: "/some/path/pkg1/dependencies/foo",
				},
			},
		},
		PURL: "a-purl-2", // intentionally a bad pURL for test fixtures
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*", cpe.Source("")),
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Locations: file.NewLocationSet(
			file.NewLocation("/some/path/pkg1"),
		),
		Metadata: pkg.DpkgDBEntry{
			Package: "package-2",
			Version: "2.0.1",
		},
		PURL: "pkg:deb/debian/package-2@2.0.1",
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*", cpe.Source("")),
		},
	})

	return catalog
}

func newDirectoryCatalogWithAuthorField() *pkg.Collection {
	catalog := pkg.NewCollection()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.PythonPkg,
		FoundBy: "the-cataloger-1",
		Locations: file.NewLocationSet(
			file.NewLocation("/some/path/pkg1"),
		),
		Language: pkg.Python,
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicense("MIT"),
		),
		Metadata: pkg.PythonPackage{
			Name:    "package-1",
			Version: "1.0.1",
			Author:  "test-author",
			Files: []pkg.PythonFileRecord{
				{
					Path: "/some/path/pkg1/dependencies/foo",
				},
			},
		},
		PURL: "a-purl-2", // intentionally a bad pURL for test fixtures
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*", cpe.GeneratedSource),
		},
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Locations: file.NewLocationSet(
			file.NewLocation("/some/path/pkg1"),
		),
		Metadata: pkg.DpkgDBEntry{
			Package: "package-2",
			Version: "2.0.1",
		},
		PURL: "pkg:deb/debian/package-2@2.0.1",
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:*:some:package:2:*:*:*:*:*:*:*", "another-test-source"),
		},
	})

	return catalog
}
