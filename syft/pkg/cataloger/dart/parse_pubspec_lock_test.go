package dart

import (
	"os"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestParsePubspecLock(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:         "ale",
			Version:      "3.3.0",
			PURL:         "pkg:pub/ale@3.3.0?hosted_url=pub.hosted.org",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:      "ale",
				Version:   "3.3.0",
				HostedURL: "pub.hosted.org",
			},
		},
		{
			Name:         "analyzer",
			Version:      "0.40.7",
			PURL:         "pkg:pub/analyzer@0.40.7",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "analyzer",
				Version: "0.40.7",
			},
		},
		{
			Name:         "ansicolor",
			Version:      "1.1.1",
			PURL:         "pkg:pub/ansicolor@1.1.1",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "ansicolor",
				Version: "1.1.1",
			},
		},
		{
			Name:         "archive",
			Version:      "2.0.13",
			PURL:         "pkg:pub/archive@2.0.13",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "archive",
				Version: "2.0.13",
			},
		},
		{
			Name:         "args",
			Version:      "1.6.0",
			PURL:         "pkg:pub/args@1.6.0",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "args",
				Version: "1.6.0",
			},
		},
		{
			Name:         "key_binder",
			Version:      "1.11.20",
			PURL:         "pkg:pub/key_binder@1.11.20?vcs_url=git%40github.com:Workiva/key_binder.git%403f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
			Language:     pkg.Dart,
			Type:         pkg.DartPubPkg,
			MetadataType: pkg.DartPubMetadataType,
			Metadata: pkg.DartPubMetadata{
				Name:    "key_binder",
				Version: "1.11.20",
				VcsURL:  "git@github.com:Workiva/key_binder.git@3f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/pubspec.lock")
	require.NoError(t, err)

	// TODO: no relationships are under test yet
	actual, _, err := parsePubspecLock(nil, nil, source.LocationReadCloser{
		Location:   source.NewLocation(fixture.Name()),
		ReadCloser: fixture,
	})
	require.NoError(t, err)

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
