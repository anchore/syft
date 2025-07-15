package dart

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePubspecLock(t *testing.T) {
	tests := []struct {
		name                  string
		fixture               string
		expectedPackages      []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			name:    "standard pubspec.lock",
			fixture: "test-fixtures/pubspec_locks/pubspec.lock",
			expectedPackages: []pkg.Package{
				{
					Name:      "ale",
					Version:   "3.3.0",
					PURL:      "pkg:pub/ale@3.3.0?hosted_url=pub.hosted.org",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/pubspec_locks/pubspec.lock")),
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
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/pubspec_locks/pubspec.lock")),
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
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/pubspec_locks/pubspec.lock")),
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
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/pubspec_locks/pubspec.lock")),
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
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/pubspec_locks/pubspec.lock")),
					Language:  pkg.Dart,
					Type:      pkg.DartPubPkg,
					Metadata: pkg.DartPubspecLockEntry{
						Name:    "args",
						Version: "1.6.0",
					},
				},
				{
					Name:      "flutter",
					Version:   "3.24.5",
					PURL:      "pkg:pub/flutter@3.24.5",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/pubspec_locks/pubspec.lock")),
					Language:  pkg.Dart,
					Type:      pkg.DartPubPkg,
					Metadata: pkg.DartPubspecLockEntry{
						Name:    "flutter",
						Version: "3.24.5",
					},
				},
				{
					Name:      "key_binder",
					Version:   "1.11.20",
					PURL:      "pkg:pub/key_binder@1.11.20?vcs_url=git%40github.com%3AWorkiva%2Fkey_binder.git%403f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
					Locations: file.NewLocationSet(file.NewLocation("test-fixtures/pubspec_locks/pubspec.lock")),
					Language:  pkg.Dart,
					Type:      pkg.DartPubPkg,
					Metadata: pkg.DartPubspecLockEntry{
						Name:    "key_binder",
						Version: "1.11.20",
						VcsURL:  "git@github.com:Workiva/key_binder.git@3f7b3a6350e73c7dcac45301c0e18fbd42af02f7",
					},
				},
			},
			expectedRelationships: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.TestFileParser(t, test.fixture, parsePubspecLock, test.expectedPackages, test.expectedRelationships)
		})
	}
}

func Test_corruptPubspecLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/pubspec.lock").
		WithError().
		TestParser(t, parsePubspecLock)
}

func Test_missingSdkEntryPubspecLock(t *testing.T) {
	fixture := "test-fixtures/missing-sdk/pubspec.lock"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	// SDK version is missing, so flutter version cannot be determined and
	// is ignored, expecting args as only package in the list as a result.
	expected := []pkg.Package{
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
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePubspecLock, expected, expectedRelationships)
}

func Test_invalidSdkEntryPubspecLock(t *testing.T) {
	fixture := "test-fixtures/invalid-sdk/pubspec.lock"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation(fixture))

	// SDK version is invalid, so flutter version cannot be determined and
	// is ignored, expecting args as only package in the list as a result.
	expected := []pkg.Package{
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
	}

	// TODO: relationships are not under test
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePubspecLock, expected, expectedRelationships)
}

func Test_sdkVersionLookup(t *testing.T) {
	psl := &pubspecLock{
		Sdks: make(map[string]string, 5),
	}

	psl.Sdks["minVersionSdk"] = ">=0.1.2"
	psl.Sdks["rangeVersionSdk"] = ">=1.2.3 <2.0.0"
	psl.Sdks["caretVersionSdk"] = "^2.3.4"
	psl.Sdks["emptyVersionSdk"] = ""
	psl.Sdks["invalidVersionSdk"] = "not a constraint"

	var version string
	var err error

	version, err = psl.getSdkVersion("minVersionSdk")
	assert.NoError(t, err)
	assert.Equal(t, "0.1.2", version)

	version, err = psl.getSdkVersion("rangeVersionSdk")
	assert.NoError(t, err)
	assert.Equal(t, "1.2.3", version)

	version, err = psl.getSdkVersion("caretVersionSdk")
	assert.NoError(t, err)
	assert.Equal(t, "2.3.4", version)

	version, err = psl.getSdkVersion("emptyVersionSdk")
	assert.Error(t, err)
	assert.Equal(t, "", version)

	version, err = psl.getSdkVersion("invalidVersionSdk")
	assert.Error(t, err)
	assert.Equal(t, "", version)

	version, err = psl.getSdkVersion("nonexistantSdk")
	assert.Error(t, err)
	assert.Equal(t, "", version)
}

func Test_sdkVersionParser_valid(t *testing.T) {
	var version string
	var err error

	// map constraints to expected version
	patterns := map[string]string{
		"^0.0.0":                "0.0.0",
		">=0.0.0":               "0.0.0",
		"^1.23.4":               "1.23.4",
		">=1.23.4":              "1.23.4",
		"^11.22.33":             "11.22.33",
		">=11.22.33":            "11.22.33",
		"^123.123456.12345678":  "123.123456.12345678",
		">=123.123456.12345678": "123.123456.12345678",
		">=1.2.3 <2.3.4":        "1.2.3",
		">=1.2.3 random string": "1.2.3",
		">=1.2.3 >=0.1.2":       "1.2.3",
		"^1.2":                  "1.2",
		">=1.2":                 "1.2",
		"^1.2.3-rc4":            "1.2.3-rc4",
		">=1.2.3-rc4":           "1.2.3-rc4",
		"^2.34.5+hotfix6":       "2.34.5+hotfix6",
		">=2.34.5+hotfix6":      "2.34.5+hotfix6",
	}

	for constraint, expected := range patterns {
		t.Run(constraint, func(t *testing.T) {
			version, err = parseMinimumSdkVersion(constraint)
			assert.NoError(t, err)
			assert.Equal(t, expected, version)
		})
	}
}

func Test_sdkVersionParser_invalid(t *testing.T) {
	var version string
	var err error

	patterns := []string{
		"",
		"abc",
		"^abc",
		">=abc",
		"^a.b.c",
		">=a.b.c",
		"1.2.34",
		">1.2.34",
		"<=1.2.34",
		"<1.2.34",
		"^1.2.3.4",
		">=1.2.3.4",
		"^1.x.0",
		">=1.x.0",
		"^1x2x3",
		">=1x2x3",
		"^1.-2.3",
		">=1.-2.3",
		"abc <1.2.34",
		"^2.3.45hotfix6",
		">=2.3.45hotfix6",
	}

	for _, pattern := range patterns {
		version, err = parseMinimumSdkVersion(pattern)
		assert.Error(t, err)
		assert.Equalf(t, "", version, "constraint '%s'", pattern)
	}
}
