package cpp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseVcpkgManifest(t *testing.T) {

	fixture := "testdata/vcpkg/helloworld"
	// the resolver reads the vcpkg registry from a local git clone rather than cloning over the network
	// at test time. the clone is materialized just-in-time on first run (network required once) into a
	// gitignored cache dir, then reused offline on later runs.
	useLocalVcpkgRegistryCache(t)
	fileLocs := []file.Location{file.NewLocation("vcpkg.json")}
	fixtureLocationSet := file.NewLocationSet(fileLocs...)
	ctx := pkgtest.Context(t)

	fmtPkg := pkg.Package{
		Name:      "fmt",
		Version:   "11.0.2#1",
		PURL:      "pkg:vcpkg/fmt@11.0.2?port_revision=1&repository_revision=fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3&repository_url=https%3A%2F%2Fgithub.com%2Fanchore%2Fvcpkg-test-fixture&triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Description: []string{"{fmt} is an open-source formatting library providing a fast and safe alternative to C stdio and C++ iostreams."},
			FullVersion: "11.0.2#1",
			Version:     "11.0.2",
			PortVersion: 1,
			License:     "MIT",
			Name:        "fmt",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3",
				Kind:       pkg.Git,
				Repository: "https://github.com/anchore/vcpkg-test-fixture",
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
			Version:     "0.1.0",
			Name:        "hello",
			Registry:    nil,
			Triplet:     "x64-linux",
		},
	}
	vcpkgCmakeConfigPkg := pkg.Package{
		Name:      "vcpkg-cmake-config",
		Version:   "2024-05-23",
		PURL:      "pkg:vcpkg/vcpkg-cmake-config@2024-05-23?repository_revision=fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3&repository_url=https%3A%2F%2Fgithub.com%2Fanchore%2Fvcpkg-test-fixture&triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Documentation: "https://learn.microsoft.com/vcpkg/maintainers/functions/vcpkg_cmake_config_fixup",
			FullVersion:   "2024-05-23",
			Version:       "2024-05-23",
			License:       "MIT",
			Name:          "vcpkg-cmake-config",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3",
				Kind:       pkg.Git,
				Repository: "https://github.com/anchore/vcpkg-test-fixture",
			},
			Triplet: "x64-linux",
		},
	}
	vcpkgCmakePkg := pkg.Package{
		Name:      "vcpkg-cmake",
		Version:   "2024-04-23",
		PURL:      "pkg:vcpkg/vcpkg-cmake@2024-04-23?repository_revision=fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3&repository_url=https%3A%2F%2Fgithub.com%2Fanchore%2Fvcpkg-test-fixture&triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Documentation: "https://learn.microsoft.com/vcpkg/maintainers/functions/vcpkg_cmake_configure",
			FullVersion:   "2024-04-23",
			Version:       "2024-04-23",
			License:       "MIT",
			Name:          "vcpkg-cmake",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3",
				Kind:       pkg.Git,
				Repository: "https://github.com/anchore/vcpkg-test-fixture",
			},
			Triplet: "x64-linux",
		},
	}
	sampleLibPkg := pkg.Package{
		Name:      "vcpkg-sample-library",
		Version:   "1.0.2",
		PURL:      "pkg:vcpkg/vcpkg-sample-library@1.0.2?repository_revision=fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3&repository_url=https%3A%2F%2Fgithub.com%2Fanchore%2Fvcpkg-test-fixture&triplet=x64-linux",
		FoundBy:   "vcpkg-manifest-cataloger",
		Locations: fixtureLocationSet,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocationsWithContext(ctx, "MIT", fileLocs...)),
		Language:  pkg.CPP,
		Type:      pkg.VcpkgPkg,
		Metadata: &pkg.VcpkgManifest{
			Description: []string{"A sample C++ library designed to serve as a foundational example for a tutorial on packaging libraries with vcpkg."},
			FullVersion: "1.0.2",
			Version:     "1.0.2",
			License:     "MIT",
			Name:        "vcpkg-sample-library",
			Registry: &pkg.VcpkgRegistryEntry{
				Baseline:   "fbfe5a93a4b9562d88dcbc9cefca0016594ba3b3",
				Kind:       pkg.Git,
				Repository: "https://github.com/anchore/vcpkg-test-fixture",
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
			From: fmtPkg,
			To:   helloPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: vcpkgCmakePkg,
			To:   fmtPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: vcpkgCmakeConfigPkg,
			To:   fmtPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: sampleLibPkg,
			To:   helloPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: fmtPkg,
			To:   sampleLibPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: vcpkgCmakePkg,
			To:   sampleLibPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: vcpkgCmakeConfigPkg,
			To:   sampleLibPkg,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	catalogerCfg := CatalogerConfig{
		VcpkgAllowGitClone: false,
	}
	pkgtest.TestCataloger(t, fixture, NewVcpkgManifestCataloger(catalogerCfg), expectedPkgs, expectedRelationships)
}

// the registry the helloworld fixture pins; see testdata/vcpkg/helloworld/vcpkg-configuration.json
const vcpkgTestRegistryURL = "https://github.com/anchore/vcpkg-test-fixture"

// useLocalVcpkgRegistryCache points syft's cache manager at a gitignored testdata cache and ensures a local
// clone of the vcpkg test registry exists there, so the resolver resolves it offline via git.PlainOpen
// (getVcpkgGitCachePath resolves to "<syft cache root>/../vcpkg/registries/git").
func useLocalVcpkgRegistryCache(t *testing.T) {
	t.Helper()

	cacheRoot := filepath.Join("testdata", "cache")
	syftCacheRoot := filepath.Join(cacheRoot, "syft")
	registryGitDir := filepath.Join(cacheRoot, "vcpkg", "registries", "git")

	prepareVcpkgRegistryCache(t, registryGitDir)

	mgr, err := cache.NewFromDir(syftCacheRoot, 24*time.Hour)
	require.NoError(t, err)
	prev := cache.GetManager()
	cache.SetManager(mgr)
	t.Cleanup(func() { cache.SetManager(prev) })
}

// prepareVcpkgRegistryCache clones the vcpkg test registry into gitDir if a valid clone is not already present.
// the clone happens once (first run, requires network); later runs reuse it offline.
func prepareVcpkgRegistryCache(t *testing.T, gitDir string) {
	t.Helper()

	if _, err := git.PlainOpen(gitDir); err == nil {
		return // valid cache already present
	}
	// clear any partial/stale state left by an interrupted run
	require.NoError(t, os.RemoveAll(gitDir))
	require.NoError(t, os.MkdirAll(filepath.Dir(gitDir), 0o755))

	// clone into a temp sibling then atomically move into place so an interrupted or concurrent run can't
	// observe a half-written cache
	tmp, err := os.MkdirTemp(filepath.Dir(gitDir), "clone-")
	require.NoError(t, err)
	defer os.RemoveAll(tmp)

	cloneTarget := filepath.Join(tmp, "git")
	if _, err := git.PlainClone(cloneTarget, false, &git.CloneOptions{URL: vcpkgTestRegistryURL}); err != nil {
		t.Skipf("vcpkg registry cache is not present and could not be prepared (first run requires network): %v", err)
	}
	require.NoError(t, os.Rename(cloneTarget, gitDir))
}
