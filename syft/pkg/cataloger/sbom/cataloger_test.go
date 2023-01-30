package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func mustCPEs(s ...string) (c []cpe.CPE) {
	for _, i := range s {
		c = append(c, mustCPE(i))
	}
	return
}

func mustCPE(c string) cpe.CPE {
	return must(cpe.New(c))
}
func must(c cpe.CPE, e error) cpe.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func Test_parseSBOM(t *testing.T) {

	expectedPkgs := []pkg.Package{
		{
			Name:      "alpine-baselayout",
			Version:   "3.2.0-r23",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"GPL-2.0-only"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/alpine-baselayout@3.2.0-r23?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-baselayout:alpine_baselayout:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_baselayout:alpine-baselayout:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_baselayout:alpine_baselayout:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine-baselayout:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine_baselayout:3.2.0-r23:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "alpine-baselayout-data",
			Version:   "3.2.0-r23",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"GPL-2.0-only"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/alpine-baselayout-data@3.2.0-r23?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:alpine-baselayout-data:alpine-baselayout-data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-baselayout-data:alpine_baselayout_data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_baselayout_data:alpine-baselayout-data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_baselayout_data:alpine_baselayout_data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-baselayout:alpine-baselayout-data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-baselayout:alpine_baselayout_data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_baselayout:alpine-baselayout-data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_baselayout:alpine_baselayout_data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine-baselayout-data:3.2.0-r23:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine_baselayout_data:3.2.0-r23:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "alpine-keys",
			Version:   "2.4-r1",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"MIT"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/alpine-keys@2.4-r1?arch=x86_64&upstream=alpine-keys&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:alpine-keys:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine-keys:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_keys:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine_keys:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine-keys:2.4-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:alpine:alpine_keys:2.4-r1:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "apk-tools",
			Version:   "2.12.9-r3",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"GPL-2.0-only"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/apk-tools@2.12.9-r3?arch=x86_64&upstream=apk-tools&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:apk-tools:apk-tools:2.12.9-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:apk-tools:apk_tools:2.12.9-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:apk_tools:apk-tools:2.12.9-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:apk_tools:apk_tools:2.12.9-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:apk:apk-tools:2.12.9-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:apk:apk_tools:2.12.9-r3:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "busybox",
			Version:   "1.35.0-r17",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"GPL-2.0-only"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/busybox@1.35.0-r17?arch=x86_64&upstream=busybox&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:busybox:busybox:1.35.0-r17:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "ca-certificates-bundle",
			Version:   "20220614-r0",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"MPL-2.0", "AND", "MIT"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/ca-certificates-bundle@20220614-r0?arch=x86_64&upstream=ca-certificates&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:ca-certificates-bundle:ca-certificates-bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca-certificates-bundle:ca_certificates_bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca_certificates_bundle:ca-certificates-bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca_certificates_bundle:ca_certificates_bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca-certificates:ca-certificates-bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca-certificates:ca_certificates_bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca_certificates:ca-certificates-bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca_certificates:ca_certificates_bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca:ca-certificates-bundle:20220614-r0:*:*:*:*:*:*:*",
				"cpe:2.3:a:ca:ca_certificates_bundle:20220614-r0:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "libc-utils",
			Version:   "0.7.2-r3",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"BSD-2-Clause", "AND", "BSD-3-Clause"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/libc-utils@0.7.2-r3?arch=x86_64&upstream=libc-dev&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:libc-utils:libc-utils:0.7.2-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:libc-utils:libc_utils:0.7.2-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:libc_utils:libc-utils:0.7.2-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:libc_utils:libc_utils:0.7.2-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:libc:libc-utils:0.7.2-r3:*:*:*:*:*:*:*",
				"cpe:2.3:a:libc:libc_utils:0.7.2-r3:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "libcrypto1.1",
			Version:   "1.1.1s-r0",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"OpenSSL"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/libcrypto1.1@1.1.1s-r0?arch=x86_64&upstream=openssl&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:libcrypto1.1:libcrypto1.1:1.1.1s-r0:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "libssl1.1",
			Version:   "1.1.1s-r0",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"OpenSSL"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/libssl1.1@1.1.1s-r0?arch=x86_64&upstream=openssl&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:libssl1.1:libssl1.1:1.1.1s-r0:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "musl",
			Version:   "1.2.3-r1",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"MIT"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/musl@1.2.3-r1?arch=x86_64&upstream=musl&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:musl:musl:1.2.3-r1:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "musl-utils",
			Version:   "1.2.3-r1",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"MIT", "BSD", "GPL2+"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/musl-utils@1.2.3-r1?arch=x86_64&upstream=musl&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:musl-utils:musl-utils:1.2.3-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:musl-utils:musl_utils:1.2.3-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:musl_utils:musl-utils:1.2.3-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:musl_utils:musl_utils:1.2.3-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:musl:musl-utils:1.2.3-r1:*:*:*:*:*:*:*",
				"cpe:2.3:a:musl:musl_utils:1.2.3-r1:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "scanelf",
			Version:   "1.3.4-r0",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"GPL-2.0-only"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/scanelf@1.3.4-r0?arch=x86_64&upstream=pax-utils&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:scanelf:scanelf:1.3.4-r0:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "ssl_client",
			Version:   "1.35.0-r17",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"GPL-2.0-only"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/ssl_client@1.35.0-r17?arch=x86_64&upstream=busybox&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:ssl-client:ssl-client:1.35.0-r17:*:*:*:*:*:*:*",
				"cpe:2.3:a:ssl-client:ssl_client:1.35.0-r17:*:*:*:*:*:*:*",
				"cpe:2.3:a:ssl_client:ssl-client:1.35.0-r17:*:*:*:*:*:*:*",
				"cpe:2.3:a:ssl_client:ssl_client:1.35.0-r17:*:*:*:*:*:*:*",
				"cpe:2.3:a:ssl:ssl-client:1.35.0-r17:*:*:*:*:*:*:*",
				"cpe:2.3:a:ssl:ssl_client:1.35.0-r17:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "zlib",
			Version:   "1.2.12-r3",
			Type:      "apk",
			Locations: source.NewLocationSet(source.NewLocation("sbom.syft.json")),
			Licenses:  []string{"Zlib"},
			FoundBy:   "sbom-cataloger",
			PURL:      "pkg:apk/alpine/zlib@1.2.12-r3?arch=x86_64&upstream=zlib&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:zlib:zlib:1.2.12-r3:*:*:*:*:*:*:*",
			),
		},
	}

	var expectedRelationships []artifact.Relationship

	for _, p := range expectedPkgs {
		expectedRelationships = append(expectedRelationships, artifact.Relationship{
			From: p,
			To: source.Coordinates{
				RealPath: "sbom.syft.json",
			},
			Type: artifact.DescribedByRelationship,
		})
	}

	tests := []struct {
		name              string
		format            sbom.Format
		fixture           string
		wantPkgs          []pkg.Package
		wantRelationships []artifact.Relationship
		wantErr           require.ErrorAssertionFunc
	}{
		{
			name:              "parse syft JSON",
			format:            syftjson.Format(),
			fixture:           "test-fixtures/alpine/syft-json",
			wantPkgs:          expectedPkgs,
			wantRelationships: expectedRelationships,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixture).
				IgnorePackageFields("Metadata", "MetadataType").
				Expects(tt.wantPkgs, tt.wantRelationships).
				TestCataloger(t, NewSBOMCataloger())
		})
	}
}

func Test_Cataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain sbom files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"bom",
				"sbom",
				"app.syft.json",
				"app.bom",
				"app.sbom",
				"app.cdx",
				"app.spdx",
				"app.bom.json",
				"app.sbom.json",
				"app.cdx.json",
				"app.spdx.json",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewSBOMCataloger())
		})
	}
}
