package dart

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePubspecLock(t *testing.T) {
	fixture := "test-fixtures/pubspec.lock"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))
	expected := []pkg.Package{
		{
			Name:      "ale",
			Version:   "3.3.0",
			PURL:      "pkg:pub/ale@3.3.0?hosted_url=pub.hosted.org",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecLockEntry{
				Name:      "ale",
				Version:   "3.3.0",
				HostedURL: "pub.hosted.org",
			},
		},
		{
			Name:      "analyzer",
			Version:   "0.40.7",
			PURL:      "pkg:pub/analyzer@0.40.7",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecLockEntry{
				Name:    "analyzer",
				Version: "0.40.7",
			},
		},
		{
			Name:      "ansicolor",
			Version:   "1.1.1",
			PURL:      "pkg:pub/ansicolor@1.1.1",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecLockEntry{
				Name:    "ansicolor",
				Version: "1.1.1",
			},
		},
		{
			Name:      "archive",
			Version:   "2.0.13",
			PURL:      "pkg:pub/archive@2.0.13",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecLockEntry{
				Name:    "archive",
				Version: "2.0.13",
			},
		},
		{
			Name:      "args",
			Version:   "1.6.0",
			PURL:      "pkg:pub/args@1.6.0",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecLockEntry{
				Name:    "args",
				Version: "1.6.0",
			},
		},
		{
			Name:      "flutter",
			Version:   "0.0.0",
			PURL:      "pkg:pub/flutter@0.0.0",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecLockEntry{
				Name:    "flutter",
				Version: "0.0.0",
			},
		},
		{
			Name:      "key_binder",
			Version:   "1.11.20",
			PURL:      "pkg:pub/key_binder@1.11.20?vcs_url=git%40github.com:Workiva/key_binder.git%403f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
			Locations: fixtureLocationSet,
			Language:  pkg.Dart,
			Type:      pkg.DartPubPkg,
			Metadata: pkg.DartPubspecLockEntry{
				Name:    "key_binder",
				Version: "1.11.20",
				VcsURL:  "git@github.com:Workiva/key_binder.git@3f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
			},
		},
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePubspecLock, expected, expectedRelationships)
}

func Test_corruptPubspecLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/pubspec.lock").
		WithError().
		TestParser(t, parsePubspecLock)
}
