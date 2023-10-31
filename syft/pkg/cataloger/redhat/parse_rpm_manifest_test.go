package redhat

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRpmManifest(t *testing.T) {
	fixture := "test-fixtures/container-manifest-2"
	location := file.NewLocation(fixture)
	expected := []pkg.Package{
		{
			Name:      "mariner-release",
			Version:   "2.0-12.cm2",
			PURL:      "pkg:rpm/mariner-release@2.0-12.cm2?arch=noarch&upstream=mariner-release-2.0-12.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
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
		{
			Name:      "filesystem",
			Version:   "1.1-9.cm2",
			PURL:      "pkg:rpm/filesystem@1.1-9.cm2?arch=x86_64&upstream=filesystem-1.1-9.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
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
		{
			Name:      "glibc",
			Version:   "2.35-2.cm2",
			PURL:      "pkg:rpm/glibc@2.35-2.cm2?arch=x86_64&upstream=glibc-2.35-2.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
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
		{
			Name:      "openssl-libs",
			Version:   "1.1.1k-15.cm2",
			PURL:      "pkg:rpm/openssl-libs@1.1.1k-15.cm2?arch=x86_64&upstream=openssl-1.1.1k-15.cm2.src.rpm",
			Locations: file.NewLocationSet(location),
			Type:      pkg.RpmPkg,
			Metadata: pkg.RpmDBEntry{
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

	pkgtest.NewCatalogTester().
		FromFile(t, fixture).
		Expects(expected, nil).
		TestParser(t, parseRpmManifest)

}
