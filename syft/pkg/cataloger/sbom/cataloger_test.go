package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func mustCPEs(s ...string) (c []cpe.CPE) {
	for _, i := range s {
		c = append(c, cpe.Must(i, ""))
	}
	return
}

func Test_parseSBOM(t *testing.T) {
	expectedPkgs := []pkg.Package{
		{
			Name:      "alpine-baselayout",
			Version:   "3.2.0-r23",
			Type:      "apk",
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0-only")),
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0-only")),
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0-only")),
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0-only")),
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("MPL-2.0"),
				pkg.NewLicense("MIT"),
			),
			FoundBy: "sbom-cataloger",
			PURL:    "pkg:apk/alpine/ca-certificates-bundle@20220614-r0?arch=x86_64&upstream=ca-certificates&distro=alpine-3.16.3",
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("BSD-2-Clause"),
				pkg.NewLicense("BSD-3-Clause"),
			),
			FoundBy: "sbom-cataloger",
			PURL:    "pkg:apk/alpine/libc-utils@0.7.2-r3?arch=x86_64&upstream=libc-dev&distro=alpine-3.16.3",
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("OpenSSL")), // SPDX expression is not set
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("OpenSSL")), // SPDX expression is not set
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")), // SPDX expression is not set
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("MIT"),
				pkg.NewLicense("BSD"),
				pkg.NewLicense("GPL2+"), // SPDX expression is not set
			),
			FoundBy: "sbom-cataloger",
			PURL:    "pkg:apk/alpine/musl-utils@1.2.3-r1?arch=x86_64&upstream=musl&distro=alpine-3.16.3",
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("GPL-2.0-only"),
			),
			FoundBy: "sbom-cataloger",
			PURL:    "pkg:apk/alpine/scanelf@1.3.4-r0?arch=x86_64&upstream=pax-utils&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:scanelf:scanelf:1.3.4-r0:*:*:*:*:*:*:*",
			),
		},
		{
			Name:      "ssl_client",
			Version:   "1.35.0-r17",
			Type:      "apk",
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("GPL-2.0-only"),
			),
			FoundBy: "sbom-cataloger",
			PURL:    "pkg:apk/alpine/ssl_client@1.35.0-r17?arch=x86_64&upstream=busybox&distro=alpine-3.16.3",
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
			Locations: file.NewLocationSet(file.NewLocation("sbom.syft.json")),
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicense("Zlib"),
			),
			FoundBy: "sbom-cataloger",
			PURL:    "pkg:apk/alpine/zlib@1.2.12-r3?arch=x86_64&upstream=zlib&distro=alpine-3.16.3",
			CPEs: mustCPEs(
				"cpe:2.3:a:zlib:zlib:1.2.12-r3:*:*:*:*:*:*:*",
			),
		},
	}

	curlYaml := pkg.Package{
		Name:      "curl.yaml",
		Version:   "eca16600635a2ab921dbbe6998712c68fc8b6460",
		Type:      "UnknownPackage",
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("Apache-2.0")),
		Locations: file.NewLocationSet(file.NewLocation("curl-8.12.1-r3.spdx.json")),
		FoundBy:   "sbom-cataloger",
		PURL:      "pkg:github/wolfi-dev/os@eca16600635a2ab921dbbe6998712c68fc8b6460#curl.yaml",
		CPEs:      nil,
	}

	curlApk := pkg.Package{
		Name:     "curl",
		Version:  "8.12.1-r3",
		Type:     "apk",
		Licenses: pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		FoundBy:  "",
		PURL:     "pkg:apk/wolfi/curl@8.12.1-r3?arch=x86_64",
		CPEs:     nil,
	}

	curlApk2 := pkg.Package{
		Name:      "curl",
		Version:   "8.12.1-r3",
		Type:      "apk",
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		Locations: file.NewLocationSet(file.NewLocation("curl-8.12.1-r3.spdx.json")),
		FoundBy:   "sbom-cataloger",
		PURL:      "pkg:apk/wolfi/curl@8.12.1-r3?arch=x86_64",
		CPEs:      nil,
	}

	curl := pkg.Package{
		Name:      "curl",
		Version:   "8.12.1",
		Type:      "UnknownPackage",
		Locations: file.NewLocationSet(file.NewLocation("curl-8.12.1-r3.spdx.json")),
		Licenses:  pkg.NewLicenseSet(),
		FoundBy:   "sbom-cataloger",
		PURL:      "pkg:generic/curl@8.12.1?checksum=sha256%3A0341f1ed97a26c811abaebd37d62b833956792b7607ea3f15d001613c76de202&download_url=https%3A%2F%2Fcurl.se%2Fdownload%2Fcurl-8.12.1.tar.xz",
		CPEs:      nil,
	}

	curl2 := pkg.Package{
		Name:     "curl",
		Version:  "8.12.1",
		Type:     "UnknownPackage",
		Licenses: pkg.NewLicenseSet(),
		FoundBy:  "",
		PURL:     "pkg:generic/curl@8.12.1?checksum=sha256%3A0341f1ed97a26c811abaebd37d62b833956792b7607ea3f15d001613c76de202&download_url=https%3A%2F%2Fcurl.se%2Fdownload%2Fcurl-8.12.1.tar.xz",
		CPEs:     nil,
	}

	expectedPkgs2 := []pkg.Package{
		curl,
		curlApk2,
		curlYaml,
	}
	apkgdbLocation := file.NewLocationSet(file.Location{
		LocationData: file.LocationData{
			Coordinates: file.Coordinates{
				RealPath:     "/lib/apk/db/installed",
				FileSystemID: "sha256:e5e13b0c77cbb769548077189c3da2f0a764ceca06af49d8d558e759f5c232bd",
			},
		},
	})

	libSSL := pkg.Package{
		Name:      "libssl1.1",
		Version:   "1.1.1s-r0",
		Type:      "apk",
		Locations: apkgdbLocation,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("OpenSSL")),
		FoundBy:   "apkdb-cataloger",
		PURL:      "pkg:apk/alpine/libssl1.1@1.1.1s-r0?arch=x86_64&upstream=openssl&distro=alpine-3.16.3",
		CPEs: mustCPEs(
			"cpe:2.3:a:libssl1.1:libssl1.1:1.1.1s-r0:*:*:*:*:*:*:*",
		),
	}

	sslClient := pkg.Package{
		Name:      "ssl_client",
		Version:   "1.35.0-r17",
		Type:      "apk",
		Locations: apkgdbLocation,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0-only")),
		FoundBy:   "apkdb-cataloger",
		PURL:      "pkg:apk/alpine/ssl_client@1.35.0-r17?arch=x86_64&upstream=busybox&distro=alpine-3.16.3",
		CPEs: mustCPEs(
			"cpe:2.3:a:ssl-client:ssl-client:1.35.0-r17:*:*:*:*:*:*:*",
			"cpe:2.3:a:ssl-client:ssl_client:1.35.0-r17:*:*:*:*:*:*:*",
			"cpe:2.3:a:ssl_client:ssl-client:1.35.0-r17:*:*:*:*:*:*:*",
			"cpe:2.3:a:ssl_client:ssl_client:1.35.0-r17:*:*:*:*:*:*:*",
			"cpe:2.3:a:ssl:ssl-client:1.35.0-r17:*:*:*:*:*:*:*",
			"cpe:2.3:a:ssl:ssl_client:1.35.0-r17:*:*:*:*:*:*:*",
		),
	}

	baseLayout := pkg.Package{
		Name:      "alpine-baselayout",
		Version:   "3.2.0-r23",
		Type:      "apk",
		Locations: apkgdbLocation,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0-only")),
		FoundBy:   "apkdb-cataloger",
		PURL:      "pkg:apk/alpine/alpine-baselayout@3.2.0-r23?arch=x86_64&upstream=alpine-baselayout&distro=alpine-3.16.3",
		CPEs: mustCPEs(
			"cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.2.0-r23:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine-baselayout:alpine_baselayout:3.2.0-r23:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine_baselayout:alpine-baselayout:3.2.0-r23:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine_baselayout:alpine_baselayout:3.2.0-r23:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine:alpine-baselayout:3.2.0-r23:*:*:*:*:*:*:*",
			"cpe:2.3:a:alpine:alpine_baselayout:3.2.0-r23:*:*:*:*:*:*:*",
		),
	}

	busybox := pkg.Package{
		Name:      "busybox",
		Version:   "1.35.0-r17",
		Type:      "apk",
		Locations: apkgdbLocation,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("GPL-2.0-only")),
		FoundBy:   "apkdb-cataloger",
		PURL:      "pkg:apk/alpine/busybox@1.35.0-r17?arch=x86_64&upstream=busybox&distro=alpine-3.16.3",
		CPEs: mustCPEs(
			"cpe:2.3:a:busybox:busybox:1.35.0-r17:*:*:*:*:*:*:*",
		),
	}

	musl := pkg.Package{
		Name:      "musl",
		Version:   "1.2.3-r1",
		Type:      "apk",
		Locations: apkgdbLocation,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicense("MIT")),
		FoundBy:   "apkdb-cataloger",
		PURL:      "pkg:apk/alpine/musl@1.2.3-r1?arch=x86_64&upstream=musl&distro=alpine-3.16.3",
		CPEs: mustCPEs(
			"cpe:2.3:a:musl:musl:1.2.3-r1:*:*:*:*:*:*:*",
		),
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: libSSL,
			To:   sslClient,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: libSSL,
			To: file.Coordinates{
				RealPath:     "/lib/libssl.so.1.1",
				FileSystemID: "sha256:e5e13b0c77cbb769548077189c3da2f0a764ceca06af49d8d558e759f5c232bd",
			},
			Type: artifact.ContainsRelationship,
		},
		{
			From: busybox,
			To:   baseLayout,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: baseLayout,
			To: file.Coordinates{
				RealPath:     "/etc/profile.d/color_prompt.sh.disabled",
				FileSystemID: "sha256:e5e13b0c77cbb769548077189c3da2f0a764ceca06af49d8d558e759f5c232bd",
			},
			Type: artifact.ContainsRelationship,
		},
		{
			From: baseLayout,
			To: file.Coordinates{
				RealPath:     "/etc/modprobe.d/kms.conf",
				FileSystemID: "sha256:e5e13b0c77cbb769548077189c3da2f0a764ceca06af49d8d558e759f5c232bd",
			},
			Type: artifact.ContainsRelationship,
		},
		{
			From: musl,
			To:   libSSL,
			Type: artifact.DependencyOfRelationship,
		},
	}

	expectedRelationships2 := []artifact.Relationship{
		{
			From: curl,
			To:   file.Coordinates{RealPath: "curl-8.12.1-r3.spdx.json"},
			Type: artifact.DescribedByRelationship,
		},
		{
			From: curl2,
			To:   curlApk,
			Type: artifact.GeneratedFromRelationship,
		},
		{
			From: curlApk2,
			To:   file.Coordinates{RealPath: "curl-8.12.1-r3.spdx.json"},
			Type: artifact.DescribedByRelationship,
		},
		{
			From: curlYaml,
			To:   file.Coordinates{RealPath: "curl-8.12.1-r3.spdx.json"},
			Type: artifact.DescribedByRelationship,
		},
	}

	for _, p := range expectedPkgs {
		expectedRelationships = append(expectedRelationships, artifact.Relationship{
			From: p,
			To: file.Coordinates{
				RealPath: "sbom.syft.json",
			},
			Type: artifact.DescribedByRelationship,
		})
	}

	tests := []struct {
		name              string
		fixture           string
		wantPkgs          []pkg.Package
		wantRelationships []artifact.Relationship
		wantErr           require.ErrorAssertionFunc
	}{
		{
			name:              "parse syft JSON",
			fixture:           "test-fixtures/alpine/syft-json",
			wantPkgs:          expectedPkgs,
			wantRelationships: expectedRelationships,
		},
		{
			name:              "parse syft JSON with 'generated_from' packages",
			fixture:           "test-fixtures/chainguard-curl/syft-json",
			wantPkgs:          expectedPkgs2,
			wantRelationships: expectedRelationships2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixture).
				IgnorePackageFields("Metadata").
				Expects(tt.wantPkgs, tt.wantRelationships).
				TestCataloger(t, NewCataloger())
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
				TestCataloger(t, NewCataloger())
		})
	}
}

func Test_corruptSBOM(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/app.spdx.json").
		WithError().
		TestParser(t, parseSBOM)
}
