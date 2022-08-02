package rpmdb

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/go-test/deep"
)

func TestParseRpmManifest(t *testing.T) {
	location := source.NewLocation("test-path")

	fixture_path := "test-fixtures/container-manifest-2"
	expected := map[string]pkg.Package{
		"mariner-release": {
			Name:         "mariner-release",
			Version:      "2.0-12.cm2",
			Locations:    source.NewLocationSet(location),
			FoundBy:      catalogerName,
			Type:         pkg.RpmPkg,
			MetadataType: pkg.RpmdbMetadataType,
			Metadata: pkg.RpmdbMetadata{
				Name:      "mariner-release",
				Epoch:     nil,
				Arch:      "noarch",
				Release:   "12.cm2",
				Version:   "2.0",
				SourceRpm: "mariner-release-2.0-12.cm2.src.rpm",
				Size:      580,
				Vendor:    "Microsoft Corporation",
			},
		},
		"filesystem": {
			Name:         "filesystem",
			Version:      "1.1-9.cm2",
			Locations:    source.NewLocationSet(location),
			FoundBy:      catalogerName,
			Type:         pkg.RpmPkg,
			MetadataType: pkg.RpmdbMetadataType,
			Metadata: pkg.RpmdbMetadata{
				Name:      "filesystem",
				Epoch:     nil,
				Arch:      "x86_64",
				Release:   "9.cm2",
				Version:   "1.1",
				SourceRpm: "filesystem-1.1-9.cm2.src.rpm",
				Size:      7596,
				Vendor:    "Microsoft Corporation",
			},
		},
		"glibc": {
			Name:         "glibc",
			Version:      "2.35-2.cm2",
			Locations:    source.NewLocationSet(location),
			FoundBy:      catalogerName,
			Type:         pkg.RpmPkg,
			MetadataType: pkg.RpmdbMetadataType,
			Metadata: pkg.RpmdbMetadata{
				Name:      "glibc",
				Epoch:     nil,
				Arch:      "x86_64",
				Release:   "2.cm2",
				Version:   "2.35",
				SourceRpm: "glibc-2.35-2.cm2.src.rpm",
				Size:      10855265,
				Vendor:    "Microsoft Corporation",
			},
		},
		"openssl-libs": {
			Name:         "openssl-libs",
			Version:      "1.1.1k-15.cm2",
			Locations:    source.NewLocationSet(location),
			FoundBy:      catalogerName,
			Type:         pkg.RpmPkg,
			MetadataType: pkg.RpmdbMetadataType,
			Metadata: pkg.RpmdbMetadata{
				Name:      "openssl-libs",
				Epoch:     nil,
				Arch:      "x86_64",
				Release:   "15.cm2",
				Version:   "1.1.1k",
				SourceRpm: "openssl-1.1.1k-15.cm2.src.rpm",
				Size:      4365048,
				Vendor:    "Microsoft Corporation",
			},
		},
	}

	fixture, err := os.Open(fixture_path)
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseRpmManifest(location, fixture)
	if err != nil {
		t.Fatalf("failed to parse rpm manifest: %+v", err)
	}

	if len(actual) != 12 {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expected))
	}

	for _, a := range actual[0:4] {
		e := expected[a.Name]
		diffs := deep.Equal(a, e)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("diff: %+v", d)
			}
		}
	}
}
