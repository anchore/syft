package cpp

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseVcpkgManifest(t *testing.T) {

	// set builtin registry to only have git object data relevant to the test
	fixture := "test-fixtures/vcpkg/helloworld"
	fileLocs := []file.Location{file.NewLocation("vcpkg.json")}
	fixtureLocationSet := file.NewLocationSet(fileLocs...)
	ctx := pkgtest.Context()

	fmtPkg :=  pkg.Package{
		Name:      "fmt",
		Version:   "11.0.2#1",
		PURL:      "pkg:vcpkg/fmt@11.0.2%231?triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Description: []string{"{fmt} is an open-source formatting library providing a fast and safe alternative to C stdio and C++ iostreams."},
			FullVersion: "11.0.2#1",
			License:     "MIT",
			Name:        "fmt",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "6cb46da31ee44bc5d5da93d781e6d21f3a586add",
				Kind:       pkg.Git,
				Repository: "https://github.com/gabetrau/vcpkg-test-fixture",
			},
			Triplet: "x64-linux",
		},
	}
	helloPkg := pkg.Package{
		Name:      "hello",
		Version:   "0.1.0",
		PURL:      "pkg:vcpkg/hello@0.1.0?triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			FullVersion: "0.1.0",
			Name:        "hello",
			Registry:    nil,
			Triplet:     "x64-linux",
		},
	}
	vcpkgCmakeConfigPkg := pkg.Package{
		Name:      "vcpkg-cmake-config",
		Version:   "2024-05-23",
		PURL:      "pkg:vcpkg/vcpkg-cmake-config@2024-05-23?triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Documentation: "https://learn.microsoft.com/vcpkg/maintainers/functions/vcpkg_cmake_config_fixup",
			FullVersion:   "2024-05-23",
			License:       "MIT",
			Name:          "vcpkg-cmake-config",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "6cb46da31ee44bc5d5da93d781e6d21f3a586add",
				Kind:       pkg.Git,
				Repository: "https://github.com/gabetrau/vcpkg-test-fixture",
			},
			Triplet: "x64-linux",
		},
	}
	vcpkgCmakePkg := pkg.Package{
		Name:      "vcpkg-cmake",
		Version:   "2024-04-23",
		PURL:      "pkg:vcpkg/vcpkg-cmake@2024-04-23?triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Documentation: "https://learn.microsoft.com/vcpkg/maintainers/functions/vcpkg_cmake_configure",
			FullVersion:   "2024-04-23",
			License:       "MIT",
			Name:          "vcpkg-cmake",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "6cb46da31ee44bc5d5da93d781e6d21f3a586add",
				Kind:       pkg.Git,
				Repository: "https://github.com/gabetrau/vcpkg-test-fixture",
			},
			Triplet: "x64-linux",
		},
	}
	sampleLibPkg := pkg.Package{
		Name:      "vcpkg-sample-library",
		Version:   "1.0.2",
		PURL:      "pkg:vcpkg/vcpkg-sample-library@1.0.2?triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Description: []string{"A sample C++ library designed to serve as a foundational example for a tutorial on packaging libraries with vcpkg."},
			FullVersion:   "1.0.2",
			License:       "MIT",
			Name:          "vcpkg-sample-library",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "6cb46da31ee44bc5d5da93d781e6d21f3a586add",
				Kind:       pkg.Git,
				Repository: "https://github.com/gabetrau/vcpkg-test-fixture",
			},
			Triplet: "x64-linux",
		},
	}

	expectedPkgs := []pkg.Package{
		fmtPkg,
		fmtPkg,
		helloPkg,
		vcpkgCmakeConfigPkg,
		vcpkgCmakeConfigPkg,
		vcpkgCmakePkg,
		vcpkgCmakePkg,
		sampleLibPkg,
	}

	// relationships require IDs to be set to be sorted similarly
	for i := range expectedPkgs {
		expectedPkgs[i].SetID()
	}
	pkg.Sort(expectedPkgs)

	expectedRelationships := []artifact.Relationship{
		{
			From: helloPkg,
			To:   fmtPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: fmtPkg,
			To:   vcpkgCmakePkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: fmtPkg,
			To:   vcpkgCmakeConfigPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: helloPkg,
			To:   sampleLibPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: sampleLibPkg,
			To:   fmtPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: sampleLibPkg,
			To:   vcpkgCmakePkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: sampleLibPkg,
			To:   vcpkgCmakeConfigPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	catalogerCfg := CatalogerConfig{
		VcpkgAllowGitClone: true,
	}
	pkgtest.TestCataloger(t, fixture, NewVcpkgManifestCataloger(catalogerCfg), expectedPkgs, expectedRelationships)
}
