package dart

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func assertPackagesEqual(t *testing.T, actual []*pkg.Package, expected map[string]*pkg.Package) {
	assert.Len(t, actual, len(expected))
}

func TestParsePubspecLock(t *testing.T) {
	expected := map[string]*pkg.Package{
		"ale": {
			Name:         "ale",
			Version:      "3.3.0",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:      "ale",
				Version:   "3.3.0",
				HostedURL: "pub.hosted.org",
			},
		},
		"analyzer": {
			Name:         "analyzer",
			Version:      "0.40.7",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "analyzer",
				Version: "0.40.7",
			},
		},
		"ansicolor": {
			Name:         "ansicolor",
			Version:      "1.1.1",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "ansicolor",
				Version: "1.1.1",
			},
		},
		"archive": {
			Name:         "archive",
			Version:      "2.0.13",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "archive",
				Version: "2.0.13",
			},
		},
		"args": {
			Name:         "args",
			Version:      "1.6.0",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "args",
				Version: "1.6.0",
			},
		},
		"key_binder": {
			Name:         "key_binder",
			Version:      "1.11.20",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "key_binder",
				Version: "1.11.20",
				VcsURL:  "git@github.com:Workiva/key_binder.git#3f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
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
