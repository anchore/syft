package helpers

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_encodeComponentProperties(t *testing.T) {
	epoch := 2
	tests := []struct {
		name     string
		input    pkg.Package
		expected []cyclonedx.Property
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
				Locations: file.NewLocationSet(
					file.NewLocationFromCoordinates(file.Coordinates{RealPath: "test"}),
				),
				Metadata: pkg.ApkDBEntry{
					Package:       "libc-utils",
					OriginPackage: "libc-dev",
					Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
					Version:       "0.7.2-r0",
					Architecture:  "x86_64",
					URL:           "http://alpinelinux.org",
					Description:   "Meta package to pull in correct libc",
					Size:          0,
					InstalledSize: 4096,
					Dependencies:  []string{"musl-utils"},
					Provides:      []string{"so:libc.so.1"},
					Checksum:      "Q1p78yvTLG094tHE1+dToJGbmYzQE=",
					GitCommit:     "97b1c2842faa3bfa30f5811ffbf16d5ff9f1a479",
					Files:         []pkg.ApkFileRecord{},
				},
			},
			expected: []cyclonedx.Property{
				{Name: "syft:package:foundBy", Value: "cataloger"},
				{Name: "syft:package:metadataType", Value: "apk-db-entry"},
				{Name: "syft:location:0:path", Value: "test"},
				{Name: "syft:metadata:gitCommitOfApkPort", Value: "97b1c2842faa3bfa30f5811ffbf16d5ff9f1a479"},
				{Name: "syft:metadata:installedSize", Value: "4096"},
				{Name: "syft:metadata:originPackage", Value: "libc-dev"},
				{Name: "syft:metadata:provides:0", Value: "so:libc.so.1"},
				{Name: "syft:metadata:pullChecksum", Value: "Q1p78yvTLG094tHE1+dToJGbmYzQE="},
				{Name: "syft:metadata:pullDependencies:0", Value: "musl-utils"},
				{Name: "syft:metadata:size", Value: "0"},
			},
		},
		{
			name: "from dpkg",
			input: pkg.Package{
				Metadata: pkg.DpkgDBEntry{
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
			expected: []cyclonedx.Property{
				{Name: "syft:package:metadataType", Value: "dpkg-db-entry"},
				{Name: "syft:metadata:installedSize", Value: "3036"},
				{Name: "syft:metadata:source", Value: "tzdata-dev"},
				{Name: "syft:metadata:sourceVersion", Value: "1.0"},
			},
		},
		{
			name: "from go bin",
			input: pkg.Package{
				Name:     "golang.org/x/net",
				Version:  "v0.0.0-20211006190231-62292e806868",
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
				Metadata: pkg.GolangBinaryBuildinfoEntry{
					GoCompiledVersion: "1.17",
					Architecture:      "amd64",
					H1Digest:          "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k=",
				},
			},
			expected: []cyclonedx.Property{
				{Name: "syft:package:language", Value: pkg.Go.String()},
				{Name: "syft:package:metadataType", Value: "go-module-buildinfo-entry"},
				{Name: "syft:package:type", Value: "go-module"},
				{Name: "syft:metadata:architecture", Value: "amd64"},
				{Name: "syft:metadata:goCompiledVersion", Value: "1.17"},
				{Name: "syft:metadata:h1Digest", Value: "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k="},
			},
		},
		{
			name: "from go mod",
			input: pkg.Package{
				Name:     "golang.org/x/net",
				Version:  "v0.0.0-20211006190231-62292e806868",
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
				Metadata: pkg.GolangModuleEntry{
					H1Digest: "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k=",
				},
			},
			expected: []cyclonedx.Property{
				{Name: "syft:package:language", Value: pkg.Go.String()},
				{Name: "syft:package:metadataType", Value: "go-module-entry"},
				{Name: "syft:package:type", Value: "go-module"},
				{Name: "syft:metadata:h1Digest", Value: "h1:KlOXYy8wQWTUJYFgkUI40Lzr06ofg5IRXUK5C7qZt1k="},
			},
		},
		{
			name: "from rpm",
			input: pkg.Package{
				Name:    "dive",
				Version: "0.9.2-1",
				Type:    pkg.RpmPkg,
				Metadata: pkg.RpmDBEntry{
					Name:      "dive",
					Epoch:     &epoch,
					Arch:      "x86_64",
					Release:   "1",
					Version:   "0.9.2",
					SourceRpm: "dive-0.9.2-1.src.rpm",
					Size:      12406784,
					Vendor:    "",
					Files:     []pkg.RpmFileRecord{},
				},
			},
			expected: []cyclonedx.Property{
				{Name: "syft:package:metadataType", Value: "rpm-db-entry"},
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
			c := EncodeComponent(test.input)
			if test.expected == nil {
				if c.Properties != nil {
					t.Fatalf("expected no properties, got: %+v", *c.Properties)
				}
				return
			}
			assert.ElementsMatch(t, test.expected, *c.Properties)
		})
	}
}

func Test_encodeCompomentType(t *testing.T) {
	tests := []struct {
		name string
		pkg  pkg.Package
		want cyclonedx.Component
	}{
		{
			name: "non-binary package",
			pkg: pkg.Package{
				Name:    "pkg1",
				Version: "1.9.2",
				Type:    pkg.GoModulePkg,
			},
			want: cyclonedx.Component{
				Name:    "pkg1",
				Version: "1.9.2",
				Type:    cyclonedx.ComponentTypeLibrary,
				Properties: &[]cyclonedx.Property{
					{
						Name:  "syft:package:type",
						Value: "go-module",
					},
				},
			},
		},
		{
			name: "non-binary package",
			pkg: pkg.Package{
				Name:    "pkg1",
				Version: "3.1.2",
				Type:    pkg.BinaryPkg,
			},
			want: cyclonedx.Component{
				Name:    "pkg1",
				Version: "3.1.2",
				Type:    cyclonedx.ComponentTypeApplication,
				Properties: &[]cyclonedx.Property{
					{
						Name:  "syft:package:type",
						Value: "binary",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.pkg.ID()
			p := EncodeComponent(tt.pkg)
			assert.Equal(t, tt.want, p)
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
			assert.Equal(t, tt.want, DeriveBomRef(tt.pkg))
		})
	}
}

func Test_decodeComponent(t *testing.T) {
	tests := []struct {
		name         string
		component    cyclonedx.Component
		wantLanguage pkg.Language
		wantMetadata any
	}{
		{
			name: "derive language from pURL if missing",
			component: cyclonedx.Component{
				Name:       "ch.qos.logback/logback-classic",
				Version:    "1.2.3",
				PackageURL: "pkg:maven/ch.qos.logback/logback-classic@1.2.3",
				Type:       "library",
				BOMRef:     "pkg:maven/ch.qos.logback/logback-classic@1.2.3",
			},
			wantLanguage: pkg.Java,
		},
		{
			name: "handle RpmdbMetadata type without properties",
			component: cyclonedx.Component{
				Name:       "acl",
				Version:    "2.2.53-1.el8",
				PackageURL: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=x86_64&upstream=acl-2.2.53-1.el8.src.rpm&distro=centos-8",
				Type:       "library",
				BOMRef:     "pkg:rpm/centos/acl@2.2.53-1.el8?arch=x86_64&upstream=acl-2.2.53-1.el8.src.rpm&distro=centos-8",
				Properties: &[]cyclonedx.Property{
					{
						Name:  "syft:package:metadataType",
						Value: "RpmdbMetadata",
					},
				},
			},
			wantMetadata: pkg.RpmDBEntry{},
		},
		{
			name: "handle RpmdbMetadata type with properties",
			component: cyclonedx.Component{
				Name:       "acl",
				Version:    "2.2.53-1.el8",
				PackageURL: "pkg:rpm/centos/acl@2.2.53-1.el8?arch=x86_64&upstream=acl-2.2.53-1.el8.src.rpm&distro=centos-8",
				Type:       "library",
				BOMRef:     "pkg:rpm/centos/acl@2.2.53-1.el8?arch=x86_64&upstream=acl-2.2.53-1.el8.src.rpm&distro=centos-8",
				Properties: &[]cyclonedx.Property{
					{
						Name:  "syft:package:metadataType",
						Value: "RpmDBMetadata",
					},
					{
						Name:  "syft:metadata:release",
						Value: "some-release",
					},
				},
			},
			wantMetadata: pkg.RpmDBEntry{
				Release: "some-release",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := decodeComponent(&tt.component)
			if tt.wantLanguage != "" {
				assert.Equal(t, tt.wantLanguage, p.Language)
			}
			if tt.wantMetadata != nil {
				assert.Truef(t, reflect.DeepEqual(tt.wantMetadata, p.Metadata), "metadata should match: %+v != %+v", tt.wantMetadata, p.Metadata)
			}
			if tt.wantMetadata == nil && tt.wantLanguage == "" {
				t.Fatal("this is a useless test, please remove it")
			}
		})
	}
}
