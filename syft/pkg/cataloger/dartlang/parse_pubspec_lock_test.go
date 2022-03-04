package dartlang

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func assertPackagesEqual(t *testing.T, actual []*pkg.Package, expected map[string]*pkg.Package) {
	t.Helper()
	if len(actual) != len(expected) {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expected))
	}

	for _, a := range actual {
		expectedPkg, ok := expected[a.Name]
		assert.True(t, ok)
		assert.Equal(t, expectedPkg, a)
	}
}

func TestParsePubspecLock(t *testing.T) {
	expected := map[string]*pkg.Package{
		"ale": {
			Name:         "ale",
			Version:      "3.3.0",
			Language:     pkg.Dart,
			Type:         pkg.PubPkg,
			MetadataType: pkg.PubMetadataType,
			Metadata: pkg.PubMetadata{
				Name:      "ale",
				Version:   "3.3.0",
				HostedURL: "pub.hosted.org",
			},
		},
		"analyzer": {
			Name:         "analyzer",
			Version:      "0.40.7",
			Language:     pkg.Dart,
			Type:         pkg.PubPkg,
			MetadataType: pkg.PubMetadataType,
			Metadata: pkg.PubMetadata{
				Name:    "analyzer",
				Version: "0.40.7",
			},
		},
		"ansicolor": {
			Name:         "ansicolor",
			Version:      "1.1.1",
			Language:     pkg.Dart,
			Type:         pkg.PubPkg,
			MetadataType: pkg.PubMetadataType,
			Metadata: pkg.PubMetadata{
				Name:    "ansicolor",
				Version: "1.1.1",
			},
		},
		"archive": {
			Name:         "archive",
			Version:      "2.0.13",
			Language:     pkg.Dart,
			Type:         pkg.PubPkg,
			MetadataType: pkg.PubMetadataType,
			Metadata: pkg.PubMetadata{
				Name:    "archive",
				Version: "2.0.13",
			},
		},
		"args": {
			Name:         "args",
			Version:      "1.6.0",
			Language:     pkg.Dart,
			Type:         pkg.PubPkg,
			MetadataType: pkg.PubMetadataType,
			Metadata: pkg.PubMetadata{
				Name:    "args",
				Version: "1.6.0",
			},
		},
		"key_binder": {
			Name:         "key_binder",
			Version:      "1.11.20",
			Language:     pkg.Dart,
			Type:         pkg.PubPkg,
			MetadataType: pkg.PubMetadataType,
			Metadata: pkg.PubMetadata{
				Name:    "key_binder",
				Version: "1.11.20",
				VcsURL:  "git@github.com:Workiva/key_binder.git%403f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/pubspec.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, _, err := parsePubspecLock(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse pubspec.lock: %+v", err)
	}

	assertPackagesEqual(t, actual, expected)
}
