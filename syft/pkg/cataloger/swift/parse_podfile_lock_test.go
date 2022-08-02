package swift

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParsePodfileLock(t *testing.T) {
	expected := []*pkg.Package{
		{
			Name:         "GlossButtonNode",
			Version:      "3.1.2",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "GlossButtonNode",
				Version: "3.1.2",
				PkgHash: "4ea1197a744f2fb5fb875fe31caf17ded4762e8f",
			},
		},
		{
			Name:         "PINCache",
			Version:      "3.0.3",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "PINCache",
				Version: "3.0.3",
				PkgHash: "7a8fc1a691173d21dbddbf86cd515de6efa55086",
			},
		},
		{
			Name:         "PINCache/Arc-exception-safe",
			Version:      "3.0.3",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "PINCache/Arc-exception-safe",
				Version: "3.0.3",
				PkgHash: "7a8fc1a691173d21dbddbf86cd515de6efa55086",
			},
		},
		{
			Name:         "PINCache/Core",
			Version:      "3.0.3",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "PINCache/Core",
				Version: "3.0.3",
				PkgHash: "7a8fc1a691173d21dbddbf86cd515de6efa55086",
			},
		},
		{
			Name:         "PINOperation",
			Version:      "1.2.1",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "PINOperation",
				Version: "1.2.1",
				PkgHash: "00c935935f1e8cf0d1e2d6b542e75b88fc3e5e20",
			},
		},
		{
			Name:         "PINRemoteImage/Core",
			Version:      "3.0.3",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "PINRemoteImage/Core",
				Version: "3.0.3",
				PkgHash: "f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			},
		},
		{
			Name:         "PINRemoteImage/iOS",
			Version:      "3.0.3",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "PINRemoteImage/iOS",
				Version: "3.0.3",
				PkgHash: "f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			},
		},
		{
			Name:         "PINRemoteImage/PINCache",
			Version:      "3.0.3",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "PINRemoteImage/PINCache",
				Version: "3.0.3",
				PkgHash: "f1295b29f8c5e640e25335a1b2bd9d805171bd01",
			},
		},
		{
			Name:         "Reveal-SDK",
			Version:      "33",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Reveal-SDK",
				Version: "33",
				PkgHash: "effba1c940b8337195563c425a6b5862ec875caa",
			},
		},
		{
			Name:         "SwiftGen",
			Version:      "6.5.1",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "SwiftGen",
				Version: "6.5.1",
				PkgHash: "a6d22010845f08fe18fbdf3a07a8e380fd22e0ea",
			},
		},
		{
			Name:         "Texture",
			Version:      "3.1.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Texture",
				Version: "3.1.0",
				PkgHash: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:         "Texture/AssetsLibrary",
			Version:      "3.1.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Texture/AssetsLibrary",
				Version: "3.1.0",
				PkgHash: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:         "Texture/Core",
			Version:      "3.1.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Texture/Core",
				Version: "3.1.0",
				PkgHash: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:         "Texture/MapKit",
			Version:      "3.1.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Texture/MapKit",
				Version: "3.1.0",
				PkgHash: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:         "Texture/Photos",
			Version:      "3.1.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Texture/Photos",
				Version: "3.1.0",
				PkgHash: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:         "Texture/PINRemoteImage",
			Version:      "3.1.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Texture/PINRemoteImage",
				Version: "3.1.0",
				PkgHash: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:         "Texture/Video",
			Version:      "3.1.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "Texture/Video",
				Version: "3.1.0",
				PkgHash: "2e8ab2519452515f7f5a520f5a8f7e0a413abfa3",
			},
		},
		{
			Name:         "TextureSwiftSupport",
			Version:      "3.13.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "TextureSwiftSupport",
				Version: "3.13.0",
				PkgHash: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:         "TextureSwiftSupport/Components",
			Version:      "3.13.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "TextureSwiftSupport/Components",
				Version: "3.13.0",
				PkgHash: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:         "TextureSwiftSupport/Experiments",
			Version:      "3.13.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "TextureSwiftSupport/Experiments",
				Version: "3.13.0",
				PkgHash: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:         "TextureSwiftSupport/Extensions",
			Version:      "3.13.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "TextureSwiftSupport/Extensions",
				Version: "3.13.0",
				PkgHash: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:         "TextureSwiftSupport/LayoutSpecBuilders",
			Version:      "3.13.0",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "TextureSwiftSupport/LayoutSpecBuilders",
				Version: "3.13.0",
				PkgHash: "c515c7927fab92d0d9485f49b885b8c5de34fbfb",
			},
		},
		{
			Name:         "TinyConstraints",
			Version:      "4.0.2",
			Language:     pkg.Swift,
			Type:         pkg.CocoapodsPkg,
			MetadataType: pkg.CocoapodsMetadataType,
			Metadata: pkg.CocoapodsMetadata{
				Name:    "TinyConstraints",
				Version: "4.0.2",
				PkgHash: "7b7ccc0c485bb3bb47082138ff28bc33cd49897f",
			},
		},
	}

	fixture, err := os.Open("test-fixtures/Podfile.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parsePodfileLock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}
