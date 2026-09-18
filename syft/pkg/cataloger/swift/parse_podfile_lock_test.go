package swift

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParsePodfileLock(t *testing.T) {
	fixture := "testdata/Podfile.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "GlossButtonNode",
			Version:   "3.1.2",
			PURL:      "pkg:cocoapods/GlossButtonNode@3.1.2",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "4ea1197a744f2fb5fb875fe31caf17ded4762e8f",
			},
		},
		{
			Name:      "PINCache",
			Version:   "3.0.3",
			PURL:      "pkg:cocoapods/PINCache@3.0.3",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "7a8fc1a691173d21dbddbf86cd515de6efa55086",
			},
		},
		{
			Name:      "PINCache/Arc-exception-safe",
			Version:   "3.0.3",
			PURL:      "pkg:cocoapods/PINCache%2FArc-exception-safe@3.0.3",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "7a8fc1a691173d21dbddbf86cd515de6efa55086",
			},
		},
		{
			Name:      "PINCache/Core",
			Version:   "3.0.3",
			PURL:      "pkg:cocoapods/PINCache%2FCore@3.0.3",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "7a8fc1a691173d21dbddbf86cd515de6efa55086",
			},
		},
		{
			Name:      "PINOperation",
			Version:   "1.2.1",
			PURL:      "pkg:cocoapods/PINOperation@1.2.1",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "00c935935f1e8cf0d1e2d6b542e75b88fc3e5e20",
			},
		},
		{
			Name:      "PINRemoteImage/Core",
			Version:   "3.0.3",
			PURL:      "pkg:cocoapods/PINRemoteImage%2FCore@3.0.3",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			},
		},
		{
			Name:      "PINRemoteImage/iOS",
			Version:   "3.0.3",
			PURL:      "pkg:cocoapods/PINRemoteImage%2FiOS@3.0.3",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			},
		},
		{
			Name:      "PINRemoteImage/PINCache",
			Version:   "3.0.3",
			PURL:      "pkg:cocoapods/PINRemoteImage%2FPINCache@3.0.3",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			},
		},
		{
			Name:      "Reveal-SDK",
			Version:   "33",
			PURL:      "pkg:cocoapods/Reveal-SDK@33",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "effba1c940b8337195563c425a6b5862ec875caa",
			},
		},
		{
			Name:      "SwiftGen",
			Version:   "6.5.1",
			PURL:      "pkg:cocoapods/SwiftGen@6.5.1",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "a6d22010845f08fe18fbdf3a07a8e380fd22e0ea",
			},
		},
		{
			Name:      "Texture",
			Version:   "3.1.0",
			PURL:      "pkg:cocoapods/Texture@3.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:      "Texture/AssetsLibrary",
			Version:   "3.1.0",
			PURL:      "pkg:cocoapods/Texture%2FAssetsLibrary@3.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:      "Texture/Core",
			Version:   "3.1.0",
			PURL:      "pkg:cocoapods/Texture%2FCore@3.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:      "Texture/MapKit",
			Version:   "3.1.0",
			PURL:      "pkg:cocoapods/Texture%2FMapKit@3.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:      "Texture/Photos",
			Version:   "3.1.0",
			PURL:      "pkg:cocoapods/Texture%2FPhotos@3.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:      "Texture/PINRemoteImage",
			Version:   "3.1.0",
			PURL:      "pkg:cocoapods/Texture%2FPINRemoteImage@3.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:      "Texture/Video",
			Version:   "3.1.0",
			PURL:      "pkg:cocoapods/Texture%2FVideo@3.1.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:      "TextureSwiftSupport",
			Version:   "3.13.0",
			PURL:      "pkg:cocoapods/TextureSwiftSupport@3.13.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:      "TextureSwiftSupport/Components",
			Version:   "3.13.0",
			PURL:      "pkg:cocoapods/TextureSwiftSupport%2FComponents@3.13.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:      "TextureSwiftSupport/Experiments",
			Version:   "3.13.0",
			PURL:      "pkg:cocoapods/TextureSwiftSupport%2FExperiments@3.13.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:      "TextureSwiftSupport/Extensions",
			Version:   "3.13.0",
			PURL:      "pkg:cocoapods/TextureSwiftSupport%2FExtensions@3.13.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:      "TextureSwiftSupport/LayoutSpecBuilders",
			Version:   "3.13.0",
			PURL:      "pkg:cocoapods/TextureSwiftSupport%2FLayoutSpecBuilders@3.13.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:      "TinyConstraints",
			Version:   "4.0.2",
			PURL:      "pkg:cocoapods/TinyConstraints@4.0.2",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "7b7ccc0c485bb3bb47082138ff28bc33cd49897f",
			},
		},
	}

	// TODO: no relationships are under test yet
	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePodfileLock, expectedPkgs, expectedRelationships)
}

func TestParsePodfileLock_externalSources(t *testing.T) {
	// A pod under EXTERNAL SOURCES with a `:path:` is built from a podspec in
	// the working tree, so its version is generated rather than released --
	// Flutter hardcodes `s.version = '1.0.0'`. A `:git:` pod names a real
	// upstream revision, and a pod from a spec repo has no external source at
	// all. Consumers of the SBOM need to tell the three apart.
	fixture := "testdata/Podfile-external-sources.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	expectedPkgs := []pkg.Package{
		{
			Name:      "Analytics",
			Version:   "1.4.0",
			PURL:      "pkg:cocoapods/Analytics@1.4.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum:               "3b7a1bf0b8e4b0c6f3c2d1a09e8f7b6c5d4e3f21",
				ExternalSourceKind:     "git",
				ExternalSourceLocation: "https://github.com/example/analytics.git",
			},
		},
		{
			Name:      "Flutter",
			Version:   "1.0.0",
			PURL:      "pkg:cocoapods/Flutter@1.0.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum:               "e0871f40cf51350855a761d2e70bf5af5b9b5de7",
				ExternalSourceKind:     "path",
				ExternalSourceLocation: "Flutter",
			},
		},
		{
			Name:      "GlossButtonNode",
			Version:   "3.1.2",
			PURL:      "pkg:cocoapods/GlossButtonNode@3.1.2",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "4ea1197a744f2fb5fb875fe31caf17ded4762e8f",
			},
		},
		{
			// a subspec inherits the external source of its root pod
			Name:      "Flutter/Core",
			Version:   "1.0.0",
			PURL:      "pkg:cocoapods/Flutter%2FCore@1.0.0",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum:               "e0871f40cf51350855a761d2e70bf5af5b9b5de7",
				ExternalSourceKind:     "path",
				ExternalSourceLocation: "Flutter",
			},
		},
		{
			// a subspec of a spec-repo pod stays free of an external source
			Name:      "GlossButtonNode/Core",
			Version:   "3.1.2",
			PURL:      "pkg:cocoapods/GlossButtonNode%2FCore@3.1.2",
			Locations: locations,
			Language:  pkg.Swift,
			Type:      pkg.CocoapodsPkg,
			Metadata: pkg.CocoaPodfileLockEntry{
				Checksum: "4ea1197a744f2fb5fb875fe31caf17ded4762e8f",
			},
		},
	}

	var expectedRelationships []artifact.Relationship

	pkgtest.TestFileParser(t, fixture, parsePodfileLock, expectedPkgs, expectedRelationships)
}

func Test_corruptPodfile(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/glob-paths/src/Podfile.lock").
		WithError().
		TestParser(t, parsePodfileLock)
}
