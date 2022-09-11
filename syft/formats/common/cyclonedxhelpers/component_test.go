package cyclonedxhelpers

import (
	"fmt"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func Test_encodeComponentProperties(t *testing.T) {
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
				Locations: source.NewLocationSet(
					source.Location{Coordinates: source.Coordinates{RealPath: "test"}},
				),
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
				{Name: "syft:package:foundBy", Value: "cataloger"},
				{Name: "syft:location:0:path", Value: "test"},
				{Name: "syft:metadata:gitCommitOfApkPort", Value: "97b1c2842faa3bfa30f5811ffbf16d5ff9f1a479"},
				{Name: "syft:metadata:installedSize", Value: "4096"},
				{Name: "syft:metadata:originPackage", Value: "libc-dev"},
				{Name: "syft:metadata:pullChecksum", Value: "Q1p78yvTLG094tHE1+dToJGbmYzQE="},
				{Name: "syft:metadata:pullDependencies", Value: "musl-utils"},
				{Name: "syft:metadata:size", Value: "0"},
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
				{Name: "syft:package:metadataType", Value: "DpkgMetadata"},
				{Name: "syft:metadata:installedSize", Value: "3036"},
				{Name: "syft:metadata:source", Value: "tzdata-dev"},
				{Name: "syft:metadata:sourceVersion", Value: "1.0"},
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
				{Name: "syft:package:language", Value: pkg.Go.String()},
				{Name: "syft:package:metadataType", Value: "GolangBinMetadata"},
				{Name: "syft:package:type", Value: "go-module"},
				{Name: "syft:metadata:architecture", Value: "amd64"},
				{Name: "syft:metadata:goCompiledVersion", Value: "1.17"},
				{Name: "syft:metadata:h1Digest", Value: "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k="},
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
				{Name: "syft:package:metadataType", Value: "RpmdbMetadata"},
				{Name: "syft:package:type", Value: "rpm"},
				{Name: "syft:metadata:epoch", Value: "2"},
				{Name: "syft:metadata:release", Value: "1"},
				{Name: "syft:metadata:size", Value: "12406784"},
				{Name: "syft:metadata:sourceRpm", Value: "dive-0.9.2-1.src.rpm"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := encodeComponent(test.input)
			assert.Equal(t, test.expected, c.Properties)
		})
	}
}

func Test_deriveBomRef(t *testing.T) {
	pkgWithPurl := pkg.Package{
		Name:    "django",
		Version: "1.11.1",
		PURL:    "pkg:pypi/django@1.11.1",
	}
	pkgWithPurl.SetID()

	pkgWithOutPurl := pkg.Package{
		Name:    "django",
		Version: "1.11.1",
		PURL:    "",
	}
	pkgWithOutPurl.SetID()

	pkgWithBadPurl := pkg.Package{
		Name:    "django",
		Version: "1.11.1",
		PURL:    "pkg:pyjango@1.11.1",
	}
	pkgWithBadPurl.SetID()

	tests := []struct {
		name string
		pkg  pkg.Package
		want string
	}{
		{
			name: "use pURL-id hybrid",
			pkg:  pkgWithPurl,
			want: fmt.Sprintf("pkg:pypi/django@1.11.1?package-id=%s", pkgWithPurl.ID()),
		},
		{
			name: "fallback to ID when pURL is invalid",
			pkg:  pkgWithBadPurl,
			want: string(pkgWithBadPurl.ID()),
		},
		{
			name: "fallback to ID when pURL is missing",
			pkg:  pkgWithOutPurl,
			want: string(pkgWithOutPurl.ID()),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.pkg.ID()
			assert.Equal(t, tt.want, deriveBomRef(tt.pkg))
		})
	}
}

func Test_decodeComponent(t *testing.T) {
	javaComponentWithNoSyftProperties := cyclonedx.Component{
		Name:       "ch.qos.logback/logback-classic",
		Version:    "1.2.3",
		PackageURL: "pkg:maven/ch.qos.logback/logback-classic@1.2.3",
		Type:       "library",
		BOMRef:     "pkg:maven/ch.qos.logback/logback-classic@1.2.3",
	}

	tests := []struct {
		name      string
		component cyclonedx.Component
		want      pkg.Language
	}{
		{
			name:      "derive language from pURL if missing",
			component: javaComponentWithNoSyftProperties,
			want:      pkg.Java,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeComponent(&tt.component).Language)
		})
	}
}
