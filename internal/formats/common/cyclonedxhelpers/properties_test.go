package cyclonedxhelpers

import (
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/assert"
)

func Test_Properties(t *testing.T) {
	epoch := 2
	tests := []struct {
		name     string
		input    pkg.Package
		expected *[]cyclonedx.Property
	}{
		{
			name:     "no metadata",
			input:    pkg.Package{},
			expected: nil,
		},
		{
			name: "from apk",
			input: pkg.Package{
				FoundBy: "cataloger",
				Locations: []source.Location{
					{Coordinates: source.Coordinates{RealPath: "test"}},
				},
				Metadata: pkg.ApkMetadata{
					Package:          "libc-utils",
					OriginPackage:    "libc-dev",
					Maintainer:       "Natanael Copa <ncopa@alpinelinux.org>",
					Version:          "0.7.2-r0",
					License:          "BSD",
					Architecture:     "x86_64",
					URL:              "http://alpinelinux.org",
					Description:      "Meta package to pull in correct libc",
					Size:             0,
					InstalledSize:    4096,
					PullDependencies: "musl-utils",
					PullChecksum:     "Q1p78yvTLG094tHE1+dToJGbmYzQE=",
					GitCommitOfAport: "97b1c2842faa3bfa30f5811ffbf16d5ff9f1a479",
					Files:            []pkg.ApkFileRecord{},
				},
			},
			expected: &[]cyclonedx.Property{
				{Name: "foundBy", Value: "cataloger"},
				{Name: "path", Value: "test"},
				{Name: "originPackage", Value: "libc-dev"},
				{Name: "installedSize", Value: "4096"},
				{Name: "pullDependencies", Value: "musl-utils"},
				{Name: "pullChecksum", Value: "Q1p78yvTLG094tHE1+dToJGbmYzQE="},
				{Name: "gitCommitOfApkPort", Value: "97b1c2842faa3bfa30f5811ffbf16d5ff9f1a479"},
			},
		},
		{
			name: "from dpkg",
			input: pkg.Package{
				MetadataType: pkg.DpkgMetadataType,
				Metadata: pkg.DpkgMetadata{
					Package:       "tzdata",
					Version:       "2020a-0+deb10u1",
					Source:        "tzdata-dev",
					SourceVersion: "1.0",
					Architecture:  "all",
					InstalledSize: 3036,
					Maintainer:    "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
					Files:         []pkg.DpkgFileRecord{},
				},
			},
			expected: &[]cyclonedx.Property{
				{Name: "metadataType", Value: "DpkgMetadata"},
				{Name: "source", Value: "tzdata-dev"},
				{Name: "sourceVersion", Value: "1.0"},
				{Name: "installedSize", Value: "3036"},
			},
		},
		{
			name: "from go bin",
			input: pkg.Package{
				Name:         "golang.org/x/net",
				Version:      "v0.0.0-20211006190231-62292e806868",
				Language:     pkg.Go,
				Type:         pkg.GoModulePkg,
				MetadataType: pkg.GolangBinMetadataType,
				Metadata: pkg.GolangBinMetadata{
					GoCompiledVersion: "1.17",
					Architecture:      "amd64",
					H1Digest:          "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k=",
				},
			},
			expected: &[]cyclonedx.Property{
				{Name: "language", Value: pkg.Go.String()},
				{Name: "type", Value: "go-module"},
				{Name: "metadataType", Value: "GolangBinMetadata"},
				{Name: "goCompiledVersion", Value: "1.17"},
				{Name: "architecture", Value: "amd64"},
				{Name: "h1Digest", Value: "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k="},
			},
		},
		{
			name: "from rpm",
			input: pkg.Package{
				Name:         "dive",
				Version:      "0.9.2-1",
				Type:         pkg.RpmPkg,
				MetadataType: pkg.RpmdbMetadataType,
				Metadata: pkg.RpmdbMetadata{
					Name:      "dive",
					Epoch:     &epoch,
					Arch:      "x86_64",
					Release:   "1",
					Version:   "0.9.2",
					SourceRpm: "dive-0.9.2-1.src.rpm",
					Size:      12406784,
					License:   "MIT",
					Vendor:    "",
					Files:     []pkg.RpmdbFileRecord{},
				},
			},
			expected: &[]cyclonedx.Property{
				{Name: "type", Value: "rpm"},
				{Name: "metadataType", Value: "RpmdbMetadata"},
				{Name: "epoch", Value: "2"},
				{Name: "release", Value: "1"},
				{Name: "sourceRpm", Value: "dive-0.9.2-1.src.rpm"},
				{Name: "size", Value: "12406784"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, Properties(test.input))
		})
	}
}
