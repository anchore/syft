package spdxjson

import (
	"bytes"
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// TestSPDX3JSONRoundTrip_AllPackageTypes encodes a syft SBOM as SPDX 3.0 JSON and decodes it back, asserting
// (via a full struct diff) that every package field representable in SPDX 3.0 survives the trip.
//
// Each case provides the package to encode (input) and the package expected after decoding
// (want). They differ because some information is not representable in the SPDX 3.0 model:
//   - Locations / FoundBy are not encoded per-package (ignored in the diff below).
//   - The package ID is derived from the SPDX element ID rather than the original syft ID
//     (the unexported id field is ignored in the diff below).
//   - Type and Language are reconstructed from the package URL type.
//   - Metadata is only reconstructed for the package types with dedicated handling in the
//     SPDX encoder/decoder (apk, deb, rpm, java-archive, go-module); for all other types the
//     decoded package carries no metadata.
func TestSPDX3JSONRoundTrip_AllPackageTypes(t *testing.T) {
	ctx := context.Background()

	license := func(value string) pkg.LicenseSet {
		return pkg.NewLicenseSet(pkg.NewLicenseWithContext(ctx, value))
	}
	cpes := func(value string) []cpe.CPE {
		return []cpe.CPE{cpe.Must(value, cpe.DeclaredSource)}
	}

	cases := []struct {
		name  string
		input pkg.Package
		want  pkg.Package
	}{
		{
			name: "python package (no reconstructed metadata)",
			input: pkg.Package{
				Name:      "package-python",
				Version:   "1.0.1",
				Type:      pkg.PythonPkg,
				Language:  pkg.Python,
				Licenses:  license("MIT"),
				CPEs:      cpes("cpe:2.3:a:python:package-python:1.0.1:*:*:*:*:*:*:*"),
				Locations: file.NewLocationSet(file.NewLocation("/python")),
				PURL:      "pkg:pypi/package-python@1.0.1",
				Metadata:  pkg.PythonPackage{Name: "package-python", Version: "1.0.1"},
			},
			want: pkg.Package{
				Name:     "package-python",
				Version:  "1.0.1",
				Type:     pkg.PythonPkg,
				Language: pkg.Python,
				Licenses: license("MIT"),
				CPEs:     cpes("cpe:2.3:a:python:package-python:1.0.1:*:*:*:*:*:*:*"),
				PURL:     "pkg:pypi/package-python@1.0.1",
			},
		},
		{
			name: "npm package (no reconstructed metadata)",
			input: pkg.Package{
				Name:      "package-npm",
				Version:   "2.0.1",
				Type:      pkg.NpmPkg,
				Language:  pkg.JavaScript,
				Licenses:  license("Apache-2.0"),
				CPEs:      cpes("cpe:2.3:a:npm:package-npm:2.0.1:*:*:*:*:*:*:*"),
				Locations: file.NewLocationSet(file.NewLocation("/npm")),
				PURL:      "pkg:npm/package-npm@2.0.1",
				Metadata:  pkg.NpmPackage{Name: "package-npm", Version: "2.0.1"},
			},
			want: pkg.Package{
				Name:     "package-npm",
				Version:  "2.0.1",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Licenses: license("Apache-2.0"),
				CPEs:     cpes("cpe:2.3:a:npm:package-npm:2.0.1:*:*:*:*:*:*:*"),
				PURL:     "pkg:npm/package-npm@2.0.1",
			},
		},
		{
			name: "apk package",
			input: pkg.Package{
				Name:      "package-apk",
				Version:   "3.0",
				Type:      pkg.ApkPkg,
				Licenses:  license("GPL-2.0-only"),
				CPEs:      cpes("cpe:2.3:a:alpine:package-apk:3.0:*:*:*:*:*:*:*"),
				Locations: file.NewLocationSet(file.NewLocation("/apk")),
				PURL:      "pkg:apk/alpine/package-apk@3.0?arch=x86_64&upstream=apk-origin",
				Metadata: pkg.ApkDBEntry{
					Package:       "package-apk",
					OriginPackage: "apk-origin",
					Maintainer:    "Alpine Maintainer",
					Version:       "3.0",
					Architecture:  "x86_64",
					Description:   "the apk package",
				},
			},
			want: pkg.Package{
				Name:     "package-apk",
				Version:  "3.0",
				Type:     pkg.ApkPkg,
				Licenses: license("GPL-2.0-only"),
				CPEs:     cpes("cpe:2.3:a:alpine:package-apk:3.0:*:*:*:*:*:*:*"),
				PURL:     "pkg:apk/alpine/package-apk@3.0?arch=x86_64&upstream=apk-origin",
				Metadata: pkg.ApkDBEntry{
					Package:       "package-apk",
					OriginPackage: "apk-origin",
					Maintainer:    "Alpine Maintainer",
					Version:       "3.0",
					Architecture:  "x86_64",
					Description:   "the apk package",
				},
			},
		},
		{
			name: "deb package",
			input: pkg.Package{
				Name:      "package-deb",
				Version:   "4.0",
				Type:      pkg.DebPkg,
				Licenses:  license("LGPL-2.1-only"),
				CPEs:      cpes("cpe:2.3:a:debian:package-deb:4.0:*:*:*:*:*:*:*"),
				Locations: file.NewLocationSet(file.NewLocation("/deb")),
				PURL:      "pkg:deb/debian/package-deb@4.0?arch=amd64&upstream=deb-src%404.1",
				Metadata: pkg.DpkgDBEntry{
					Package:       "package-deb",
					Source:        "deb-src",
					Version:       "4.0",
					SourceVersion: "4.1",
					Architecture:  "amd64",
					Maintainer:    "Debian Maintainer",
				},
			},
			want: pkg.Package{
				Name:     "package-deb",
				Version:  "4.0",
				Type:     pkg.DebPkg,
				Licenses: license("LGPL-2.1-only"),
				CPEs:     cpes("cpe:2.3:a:debian:package-deb:4.0:*:*:*:*:*:*:*"),
				PURL:     "pkg:deb/debian/package-deb@4.0?arch=amd64&upstream=deb-src%404.1",
				Metadata: pkg.DpkgDBEntry{
					Package:       "package-deb",
					Source:        "deb-src",
					Version:       "4.0",
					SourceVersion: "4.1",
					Architecture:  "amd64",
					Maintainer:    "Debian Maintainer",
				},
			},
		},
		{
			name: "rpm package",
			input: pkg.Package{
				Name:      "package-rpm",
				Version:   "5.0",
				Type:      pkg.RpmPkg,
				Licenses:  license("BSD-3-Clause"),
				CPEs:      cpes("cpe:2.3:a:redhat:package-rpm:5.0:*:*:*:*:*:*:*"),
				Locations: file.NewLocationSet(file.NewLocation("/rpm")),
				PURL:      "pkg:rpm/redhat/package-rpm@5.0?arch=x86_64&upstream=rpm-src-5.0",
				Metadata: pkg.RpmDBEntry{
					Name:      "package-rpm",
					Version:   "5.0",
					Arch:      "x86_64",
					SourceRpm: "rpm-src-5.0",
					Vendor:    "RedHat",
				},
			},
			want: pkg.Package{
				Name:     "package-rpm",
				Version:  "5.0",
				Type:     pkg.RpmPkg,
				Licenses: license("BSD-3-Clause"),
				CPEs:     cpes("cpe:2.3:a:redhat:package-rpm:5.0:*:*:*:*:*:*:*"),
				PURL:     "pkg:rpm/redhat/package-rpm@5.0?arch=x86_64&upstream=rpm-src-5.0",
				Metadata: pkg.RpmDBEntry{
					Name:      "package-rpm",
					Version:   "5.0",
					Arch:      "x86_64",
					SourceRpm: "rpm-src-5.0",
					Vendor:    "RedHat",
				},
			},
		},
		{
			name: "java package",
			input: pkg.Package{
				Name:      "package-java",
				Version:   "6.0",
				Type:      pkg.JavaPkg,
				Language:  pkg.Java,
				Licenses:  license("EPL-2.0"),
				CPEs:      cpes("cpe:2.3:a:example:package-java:6.0:*:*:*:*:*:*:*"),
				Locations: file.NewLocationSet(file.NewLocation("/java")),
				PURL:      "pkg:maven/com.example/package-java@6.0",
				Metadata: pkg.JavaArchive{
					ArchiveDigests: []file.Digest{
						{Algorithm: "sha1", Value: "3b4ab96c371d913e2a88c269844b6c5fb5cbe761"},
					},
				},
			},
			want: pkg.Package{
				Name:     "package-java",
				Version:  "6.0",
				Type:     pkg.JavaPkg,
				Language: pkg.Java,
				Licenses: license("EPL-2.0"),
				CPEs:     cpes("cpe:2.3:a:example:package-java:6.0:*:*:*:*:*:*:*"),
				PURL:     "pkg:maven/com.example/package-java@6.0",
				Metadata: pkg.JavaArchive{
					ArchiveDigests: []file.Digest{
						{Algorithm: "sha1", Value: "3b4ab96c371d913e2a88c269844b6c5fb5cbe761"},
					},
				},
			},
		},
		{
			name: "go module package",
			input: pkg.Package{
				Name:      "package-go",
				Version:   "7.0",
				Type:      pkg.GoModulePkg,
				Language:  pkg.Go,
				Licenses:  license("MPL-2.0"),
				CPEs:      cpes("cpe:2.3:a:example:package-go:7.0:*:*:*:*:*:*:*"),
				Locations: file.NewLocationSet(file.NewLocation("/go")),
				PURL:      "pkg:golang/example.com/package-go@7.0",
				Metadata: pkg.GolangBinaryBuildinfoEntry{
					H1Digest: "h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=",
				},
			},
			want: pkg.Package{
				Name:     "package-go",
				Version:  "7.0",
				Type:     pkg.GoModulePkg,
				Language: pkg.Go,
				Licenses: license("MPL-2.0"),
				CPEs:     cpes("cpe:2.3:a:example:package-go:7.0:*:*:*:*:*:*:*"),
				PURL:     "pkg:golang/example.com/package-go@7.0",
				Metadata: pkg.GolangBinaryBuildinfoEntry{
					H1Digest: "h1:8QqcDgzrUqlUb/G2PQTWiueGozuR1884gddMywk6iLU=",
				},
			},
		},
	}

	var inputs []pkg.Package
	var want []pkg.Package
	for _, c := range cases {
		in := c.input
		in.SetID()
		inputs = append(inputs, in)
		want = append(want, c.want)
	}

	subject := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(inputs...),
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
		},
		Source: source.Description{
			Metadata: source.DirectoryMetadata{Path: "/home/app", Base: "/home/app"},
		},
	}

	cfg := DefaultEncoderConfig()
	cfg.Pretty = true
	cfg.Version = spdxutil.V3_0

	enc, err := NewFormatEncoderWithConfig(cfg)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, enc.Encode(&buf, subject))

	dec := NewFormatDecoder()

	id, version := dec.Identify(bytes.NewReader(buf.Bytes()))
	require.Equal(t, ID, id)
	require.Equal(t, spdxutil.V3_0, version)

	s, decodeID, decodeVersion, err := dec.Decode(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t, ID, decodeID)
	require.Equal(t, spdxutil.V3_0, decodeVersion)

	// the directory source should be recognized as the document root and not surface as a package
	require.Equal(t, len(want), s.Artifacts.Packages.PackageCount())

	got := s.Artifacts.Packages.Sorted()
	sortByName(want)
	sortByName(got)

	diff := cmp.Diff(want, got,
		cmpopts.IgnoreUnexported(pkg.Package{}, pkg.LicenseSet{}, file.LocationSet{}),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations", "FoundBy"),
	)
	require.Empty(t, diff, "decoded packages differ from expected (-want +got):\n%s", diff)
}

func sortByName(pkgs []pkg.Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})
}

// TestSPDX3JSONRoundTrip_FullSBOM encodes a more complete SBOM (a container image source, several
// packages, and relationships between them) as SPDX 3.0 JSON and decodes it back, verifying that
// the source description and the package relationships survive the round trip.
func TestSPDX3JSONRoundTrip_FullSBOM(t *testing.T) {
	newPkg := func(name string) pkg.Package {
		p := pkg.Package{
			Name:     name,
			Version:  "1.0",
			Type:     pkg.NpmPkg,
			Language: pkg.JavaScript,
			PURL:     "pkg:npm/" + name + "@1.0",
			Locations: file.NewLocationSet(
				file.NewLocation("/" + name),
			),
		}
		p.SetID()
		return p
	}

	app := newPkg("app")
	lib := newPkg("lib")
	dep := newPkg("dep")

	subject := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(app, lib, dep),
		},
		Relationships: []artifact.Relationship{
			// app contains lib
			{From: app, To: lib, Type: artifact.ContainsRelationship},
			// dep is a dependency of lib
			{From: dep, To: lib, Type: artifact.DependencyOfRelationship},
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
		},
		Source: source.Description{
			Name:     "some-image",
			Version:  "some-tag",
			Supplier: "some-supplier",
			Metadata: source.ImageMetadata{
				UserInput:      "some-image:some-tag",
				ManifestDigest: "sha256:abcdef0123456789",
				Architecture:   "amd64",
			},
		},
	}

	cfg := DefaultEncoderConfig()
	cfg.Pretty = true
	cfg.Version = spdxutil.V3_0

	enc, err := NewFormatEncoderWithConfig(cfg)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, enc.Encode(&buf, subject))

	dec := NewFormatDecoder()
	s, decodeID, decodeVersion, err := dec.Decode(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	require.NotNil(t, s)
	require.Equal(t, ID, decodeID)
	require.Equal(t, spdxutil.V3_0, decodeVersion)

	// the container image source is decoded as the document root rather than a package
	require.Equal(t, 3, s.Artifacts.Packages.PackageCount())

	// source information survives, and the source is not surfaced as a package
	// (the ID is re-derived from the SPDX element ID and is therefore not compared)
	require.Equal(t, "some-image", s.Source.Name)
	require.Equal(t, "some-tag", s.Source.Version)
	require.Equal(t, "some-supplier", s.Source.Supplier)
	require.IsType(t, source.ImageMetadata{}, s.Source.Metadata)
	imageMetadata := s.Source.Metadata.(source.ImageMetadata)
	// the user input is reconstructed from the image name and tag (version)
	require.Equal(t, "some-image:some-tag", imageMetadata.UserInput)
	require.Equal(t, "sha256:abcdef0123456789", imageMetadata.ManifestDigest)

	// relationships between packages survive, including direction
	type rel struct {
		from string
		to   string
		typ  artifact.RelationshipType
	}
	var got []rel
	for _, r := range s.Relationships {
		from, fromOk := r.From.(pkg.Package)
		to, toOk := r.To.(pkg.Package)
		require.True(t, fromOk, "relationship from should be a package: %+v", r.From)
		require.True(t, toOk, "relationship to should be a package: %+v", r.To)
		got = append(got, rel{from: from.Name, to: to.Name, typ: r.Type})
	}

	require.ElementsMatch(t, []rel{
		{from: "app", to: "lib", typ: artifact.ContainsRelationship},
		{from: "dep", to: "lib", typ: artifact.DependencyOfRelationship},
	}, got)
}
