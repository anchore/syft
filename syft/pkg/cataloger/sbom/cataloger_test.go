package sbom

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/sbom"
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

func Test_parseSBOM(t *testing.T) {
	expectedPkgs := getExpectedPkgs()

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
		MetadataType: pkg.ApkMetadataType,
		Metadata:     libsslMetadata(),
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
		MetadataType: pkg.ApkMetadataType,
		Metadata:     sslclientMetadata(),
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
		MetadataType: pkg.ApkMetadataType,
		Metadata:     alpineBaseLayoutMetadata(),
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
		MetadataType: pkg.ApkMetadataType,
		Metadata:     busyboxMetadata(),
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
		MetadataType: pkg.ApkMetadataType,
		Metadata:     muslMetadata(),
	}

	for i := range expectedPkgs {
		expectedPkgs[i].SetID()
	}

	musl.SetID()
	libSSL.SetID()
	sslClient.SetID()
	baseLayout.SetID()
	busybox.SetID()

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
				Expects(tt.wantPkgs, tt.wantRelationships).
				TestCataloger(t, NewSBOMCataloger())
		})
	}
}

func getExpectedPkgs() []pkg.Package {
	baseLayoutMetadata := alpineBaseLayoutMetadata()
	muslMetadataInst := muslMetadata()
	busyboxMetadataInst := busyboxMetadata()
	libsslMetadataInst := libsslMetadata()
	sslclientMetadataInst := sslclientMetadata()

	return []pkg.Package{
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
			MetadataType: pkg.ApkMetadataType,
			Metadata:     baseLayoutMetadata,
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
			MetadataType: pkg.ApkMetadataType,
			Metadata:     alpineBaseLayoutDataMetadata(),
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "alpine-keys",
				OriginPackage: "alpine-keys",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "2.4-r1",
				Architecture:  "x86_64",
				URL:           "https://alpinelinux.org",
				Description:   "Public keys for Alpine Linux packages",
				Size:          13359,
				InstalledSize: 159744,
				Dependencies:  []string{}, // p0
				Provides:      []string{}, // p0
				Checksum:      "Q1FBfIjtsEmvuqoNXpShXDcm/mjzE=",
				GitCommit:     "aab68f8c9ab434a46710de8e12fb3206e2930a59",
				Files: []pkg.ApkFileRecord{
					{
						Path: "/etc",
					},
					{
						Path: "/etc/apk",
					},
					{
						Path: "/etc/apk/keys",
					},
					{
						Path: "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1OvCFSO94z97c80mIDCxqGkh2Og4=",
						}),
					},
					{
						Path: "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1v7YWZYzAWoclaLDI45jEguI7YN0=",
						}),
					},
					{
						Path: "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1NnGuDsdQOx4ZNYfB3N97eLyGPkI=",
						}),
					},
					{
						Path: "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1lZlTESNrelWTNkL/oQzmAU8a99A=",
						}),
					},
					{
						Path: "/etc/apk/keys/alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1WNW6Sy87HpJ3IdemQy8pju33Kms=",
						}),
					},
					{
						Path: "/usr",
					},
					{
						Path: "/usr/share",
					},
					{
						Path: "/usr/share/apk",
					},
					{
						Path: "/usr/share/apk/keys",
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1OvCFSO94z97c80mIDCxqGkh2Og4=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1v7YWZYzAWoclaLDI45jEguI7YN0=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1BTqS+H/UUyhQuzHwiBl47+BTKuU=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1NnGuDsdQOx4ZNYfB3N97eLyGPkI=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1Oaxdcsa6AYoPdLi0U4lO3J2we18=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1yPq+su65ksNox3uXB+DR7P18+QU=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-58e4f17d.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1MpZDNX0LeLHvSOwVUyXiXx11NN0=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-5e69ca50.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1glCQ/eJbvA5xqcswdjFrWv5Fnk0=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-60ac2099.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1XUdDEoNTtjlvrS+iunk6ziFgIpU=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1lZlTESNrelWTNkL/oQzmAU8a99A=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1WNW6Sy87HpJ3IdemQy8pju33Kms=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-616a9724.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1I9Dy6hryacL2YWXg+KlE6WvwEd4=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-616abc23.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1NSnsgmcMbU4g7j5JaNs0tVHpHVA=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-616ac3bc.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1VaMBBk4Rxv6boPLKF+I085Q8y2E=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-616adfeb.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q13hJBMHAUquPbp5jpAPFjQI2Y1vQ=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1V/a5P9pKRJb6tihE3e8O6xaPgLU=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/alpine-devel@lists.alpinelinux.org-616db30d.rsa.pub",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q13wLJrcKQajql5a1p9Q45U+ZXENA=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/aarch64",
					},
					{
						Path:        "/usr/share/apk/keys/aarch64/alpine-devel@lists.alpinelinux.org-58199dcc.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q17j9nWJkQ+wfIuVQzIFrmFZ7fSOc=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/aarch64/alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1snr+Q1UbfHyCr/cmmtVvMIS7SGs=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/armhf",
					},
					{
						Path:        "/usr/share/apk/keys/armhf/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1U9QtsdN+rYZ9Zh76EfXy00JZHMg=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/armhf/alpine-devel@lists.alpinelinux.org-616a9724.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1bC+AdQ0qWBTmefXiI0PvmYOJoVQ=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/armv7",
					},
					{
						Path:        "/usr/share/apk/keys/armv7/alpine-devel@lists.alpinelinux.org-524d27bb.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1U9QtsdN+rYZ9Zh76EfXy00JZHMg=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/armv7/alpine-devel@lists.alpinelinux.org-616adfeb.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1xbIVu7ScwqGHxXGwI22aSe5OdUY=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/mips64",
					},
					{
						Path:        "/usr/share/apk/keys/mips64/alpine-devel@lists.alpinelinux.org-5e69ca50.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1hCZdFx+LvzbLtPs753je78gEEBQ=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/ppc64le",
					},
					{
						Path:        "/usr/share/apk/keys/ppc64le/alpine-devel@lists.alpinelinux.org-58cbb476.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1t21dhCLbTJmAHXSCeOMq/2vfSgo=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/ppc64le/alpine-devel@lists.alpinelinux.org-616abc23.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1PS9zNIPJanC8qcsc5qarEWqhV5Q=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/riscv64",
					},
					{
						Path:        "/usr/share/apk/keys/riscv64/alpine-devel@lists.alpinelinux.org-60ac2099.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1NVPbZavaXpsItFwQYDWbpor7yYE=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/riscv64/alpine-devel@lists.alpinelinux.org-616db30d.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1U6tfuKRy5J8C6iaKPMZaT/e8tbA=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/s390x",
					},
					{
						Path:        "/usr/share/apk/keys/s390x/alpine-devel@lists.alpinelinux.org-58e4f17d.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1sjbV2r2w0Ih2vwdzC4Jq6UI7cMQ=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/s390x/alpine-devel@lists.alpinelinux.org-616ac3bc.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1l09xa7RnbOIC1dI9FqbaCfS/GXY=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/x86",
					},
					{
						Path:        "/usr/share/apk/keys/x86/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1Ii51i7Nrc4uft14HhqugaUqdH64=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/x86/alpine-devel@lists.alpinelinux.org-5243ef4b.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1Y49eVxhpvftbQ3yAdvlLfcrPLTU=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/x86/alpine-devel@lists.alpinelinux.org-61666e3f.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1HjdvcVkpBZzr1aSe3p7oQfAtm/E=",
						}),
					},
					{
						Path: "/usr/share/apk/keys/x86_64",
					},
					{
						Path:        "/usr/share/apk/keys/x86_64/alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1Ii51i7Nrc4uft14HhqugaUqdH64=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/x86_64/alpine-devel@lists.alpinelinux.org-5261cecb.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1AUFY+fwSBTcrYetjT7NHvafrSQc=",
						}),
					},
					{
						Path:        "/usr/share/apk/keys/x86_64/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1qKA23VzMUDle+Dqnrr5Kz+Xvty4=",
						}),
					},
				},
			},
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "apk-tools",
				OriginPackage: "apk-tools",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "2.12.9-r3",
				Architecture:  "x86_64",
				URL:           "https://gitlab.alpinelinux.org/alpine/apk-tools",
				Description:   "Alpine Package Keeper - package manager for alpine",
				Size:          120745,
				InstalledSize: 307200,
				Dependencies: []string{
					"musl>=1.2",
					"ca-certificates-bundle",
					"so:libc.musl-x86_64.so.1",
					"so:libcrypto.so.1.1",
					"so:libssl.so.1.1",
					"so:libz.so.1",
				},
				Provides: []string{
					"so:libapk.so.3.12.0=3.12.0",
					"cmd:apk=2.12.9-r3",
				},
				Checksum:  "Q1VFFFWMKjB9aRkehIATc5kwgAhlU=",
				GitCommit: "34d90ac8388e88126893f5d27ea35d304e65e5ab",
				Files: []pkg.ApkFileRecord{
					{
						Path: "/etc",
					},
					{
						Path: "/etc/apk",
					},
					{
						Path: "/etc/apk/keys",
					},
					{
						Path: "/etc/apk/protected_paths.d",
					},
					{
						Path: "/lib",
					},
					{
						Path:        "/lib/libapk.so.3.12.0",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1kVeagJvcGMIKp8ijGOxaZD08ONs=",
						}),
					},
					{
						Path: "/sbin",
					},
					{
						Path:        "/sbin/apk",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1P1oUBG/VMMhnndf2fBXsZXBjHVE=",
						}),
					},
					{
						Path: "/var",
					},
					{
						Path: "/var/cache",
					},
					{
						Path: "/var/cache/misc",
					},
					{
						Path: "/var/lib",
					},
					{
						Path: "/var/lib/apk",
					},
				},
			},
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
			MetadataType: pkg.ApkMetadataType,
			Metadata:     busyboxMetadataInst,
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "ca-certificates-bundle",
				OriginPackage: "ca-certificates",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "20220614-r0",
				Architecture:  "x86_64",
				URL:           "https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/",
				Description:   "Pre generated bundle of Mozilla certificates",
				Size:          125920,
				InstalledSize: 233472,
				Dependencies:  []string{},
				Provides: []string{
					"ca-certificates-cacert=20220614-r0",
				},
				Checksum:  "Q1huqjigIP7ZNHBueDUmNnT6PpToI=",
				GitCommit: "bb51fa7743320ac61f76e181cca84daa9977573e",
				Files: []pkg.ApkFileRecord{
					{
						Path: "/etc",
					},
					{
						Path: "/etc/ssl",
					},
					{
						Path:        "/etc/ssl/cert.pem",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1Nj6gTBdkZpTFW/obJGdpfvK0StA=",
						}),
					},
					{
						Path: "/etc/ssl/certs",
					},
					{
						Path: "/etc/ssl/certs/ca-certificates.crt",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1D8ljYj7pXsRq4d/eHGNYB0GY1+I=",
						}),
					},
				},
			},
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "libc-utils",
				OriginPackage: "libc-dev",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "0.7.2-r3",
				Architecture:  "x86_64",
				URL:           "https://alpinelinux.org",
				Description:   "Meta package to pull in correct libc",
				Size:          1480,
				InstalledSize: 4096,
				Dependencies: []string{
					"musl-utils",
				},
				Provides:  []string{},
				Checksum:  "Q1O4GFJRvHz95tPjO84qpEvkNVwDw=",
				GitCommit: "60424133be2e79bbfeff3d58147a22886f817ce2",
				Files:     []pkg.ApkFileRecord{},
			},
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "libcrypto1.1",
				OriginPackage: "openssl",
				Maintainer:    "Timo Teras <timo.teras@iki.fi>",
				Version:       "1.1.1s-r0",
				Architecture:  "x86_64",
				URL:           "https://www.openssl.org/",
				Description:   "Crypto library from openssl",
				Size:          1212869,
				InstalledSize: 2772992,
				Dependencies: []string{
					"so:libc.musl-x86_64.so.1",
				},
				Provides: []string{
					"so:libcrypto.so.1.1=1.1",
				},
				Checksum:  "Q1sntUdrpKbXw81vASa482yLXNEp8=",
				GitCommit: "46b66114372a5b408ec19d3a0a0faf4aa111a36f",
				Files: []pkg.ApkFileRecord{
					{
						Path: "/etc",
					},
					{
						Path: "/etc/ssl",
					},
					{
						Path: "/etc/ssl/ct_log_list.cnf",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1olh8TpdAi2QnTl4FK3TjdUiSwTo=",
						}),
					},
					{
						Path: "/etc/ssl/ct_log_list.cnf.dist",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1olh8TpdAi2QnTl4FK3TjdUiSwTo=",
						}),
					},
					{
						Path: "/etc/ssl/openssl.cnf",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1wGuxVEOK9iGLj1i8D3BSBnT7MJA=",
						}),
					},
					{
						Path: "/etc/ssl/openssl.cnf.dist",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1wGuxVEOK9iGLj1i8D3BSBnT7MJA=",
						}),
					},
					{
						Path: "/etc/ssl/certs",
					},
					{
						Path: "/etc/ssl/misc",
					},
					{
						Path:        "/etc/ssl/misc/CA.pl",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1IACevKhK93GYBHp96Ie26jgZ17s=",
						}),
					},
					{
						Path:        "/etc/ssl/misc/tsget",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q13NVgfr7dQUuGYxur0tNalH6EIjU=",
						}),
					},
					{
						Path:        "/etc/ssl/misc/tsget.pl",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1B4a6x5Xv8BnIXP9fafuqopvrtD0=",
						}),
					},
					{
						Path: "/etc/ssl/private",
					},
					{
						Path: "/lib",
					},
					{
						Path:        "/lib/libcrypto.so.1.1",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1lYfJOxQT2Pc/ktEQt5eG4f3FLGQ=",
						}),
					},
					{
						Path: "/usr",
					},
					{
						Path: "/usr/lib",
					},
					{
						Path:        "/usr/lib/libcrypto.so.1.1",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1T2si+c7ts7sgDxQYve4B3i1Dgo0=",
						}),
					},
					{
						Path: "/usr/lib/engines-1.1",
					},
					{
						Path:        "/usr/lib/engines-1.1/afalg.so",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q11UvSn9HY0EtbzWGYm8LNatQrK/Y=",
						}),
					},
					{
						Path:        "/usr/lib/engines-1.1/capi.so",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1Z+cQuXE87JZm1iQYBohJtw6fjbs=",
						}),
					},
					{
						Path:        "/usr/lib/engines-1.1/padlock.so",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1ojt69UgLTXJSYj4gNJH/AMTeUQ8=",
						}),
					},
				},
			},
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
			MetadataType: pkg.ApkMetadataType,
			Metadata:     libsslMetadataInst,
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
			MetadataType: pkg.ApkMetadataType,
			Metadata:     muslMetadataInst,
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "musl-utils",
				OriginPackage: "musl",
				Maintainer:    "Timo Teräs <timo.teras@iki.fi>",
				Version:       "1.2.3-r1",
				Architecture:  "x86_64",
				URL:           "https://musl.libc.org/",
				Description:   "the musl c library (libc) implementation",
				Size:          36959,
				InstalledSize: 135168,
				Dependencies: []string{
					"scanelf",
					"so:libc.musl-x86_64.so.1",
				},
				Provides: []string{
					"cmd:getconf=1.2.3-r1",
					"cmd:getent=1.2.3-r1",
					"cmd:iconv=1.2.3-r1",
					"cmd:ldconfig=1.2.3-r1",
					"cmd:ldd=1.2.3-r1",
				},
				Checksum:  "Q1Avw82bzBMrlEuyKE1i1UEPK0V2Q=",
				GitCommit: "6711e7bdc190b184ec2db78d8ab5ebf06917ae78",
				Files: []pkg.ApkFileRecord{
					{
						Path: "/sbin",
					},
					{
						Path:        "/sbin/ldconfig",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1Kja2+POZKxEkUOZqwSjC6kmaED4=",
						}),
					},
					{
						Path: "/usr",
					},
					{
						Path: "/usr/bin",
					},
					{
						Path:        "/usr/bin/getconf",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1vGW6zqxwLuUVOBx6Uzf8N/hproQ=",
						}),
					},
					{
						Path:        "/usr/bin/getent",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1zszN2Pw+TEbY4SmfOguLKmmIazA=",
						}),
					},
					{
						Path:        "/usr/bin/iconv",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1UrvY/MROqlTgaScif5n9GLw9Rt8=",
						}),
					},
					{
						Path:        "/usr/bin/ldd",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1yFAhGggmL7ERgbIA7KQxyTzf3ks=",
						}),
					},
				},
			},
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "scanelf",
				OriginPackage: "pax-utils",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "1.3.4-r0",
				Architecture:  "x86_64",
				URL:           "https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities",
				Description:   "Scan ELF binaries for stuff",
				Size:          36745,
				InstalledSize: 94208,
				Dependencies: []string{
					"so:libc.musl-x86_64.so.1",
				},
				Provides: []string{
					"cmd:scanelf=1.3.4-r0",
				},
				Checksum:  "Q1Gcqe+ND8DFOlhM3R0o5KyZjR2oE=",
				GitCommit: "d7ae612a3cc5f827289d915783b4cbf8c7207947",
				Files: []pkg.ApkFileRecord{
					{
						Path: "/usr",
					},
					{
						Path: "/usr/bin",
					},
					{
						Path:        "/usr/bin/scanelf",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1YPb72qHJJvTH6mJkN9DuExFQQh8=",
						}),
					},
				},
			},
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
			MetadataType: pkg.ApkMetadataType,
			Metadata:     sslclientMetadataInst,
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
			MetadataType: pkg.ApkMetadataType,
			Metadata: pkg.ApkMetadata{
				Package:       "zlib",
				OriginPackage: "zlib",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "1.2.12-r3",
				Architecture:  "x86_64",
				URL:           "https://zlib.net/",
				Description:   "A compression/decompression Library",
				Size:          53346,
				InstalledSize: 110592,
				Dependencies: []string{
					"so:libc.musl-x86_64.so.1",
				},
				Provides: []string{
					"so:libz.so.1=1.2.12",
				},
				Checksum:  "Q1Ekuqm/0CPywDCKEbEwhsPCw+z9E=",
				GitCommit: "57ce38bde7ce42964b664c137935cf2de803ac44",
				Files: []pkg.ApkFileRecord{
					{
						Path: "/lib",
					},
					{
						Path:        "/lib/libz.so.1",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "777",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1+aBjyJ7dmLatVkyqCNnAChlDZh8=",
						}),
					},
					{
						Path:        "/lib/libz.so.1.2.12",
						OwnerUID:    "0",
						OwnerGID:    "0",
						Permissions: "755",
						Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
							Algorithm: "'Q1'+base64(sha1)",
							Value:     "Q1x/qx/7zlM20k7fLfVee7A4WLOC8=",
						}),
					},
				},
			},
		},
	}
}

func sslclientMetadata() pkg.ApkMetadata {
	return pkg.ApkMetadata{
		Package:       "ssl_client",
		OriginPackage: "busybox",
		Maintainer:    "Sören Tempel <soeren+alpine@soeren-tempel.net>",
		Version:       "1.35.0-r17",
		Architecture:  "x86_64",
		URL:           "https://busybox.net/",
		Description:   "EXternal ssl_client for busybox wget",
		Size:          5004,
		InstalledSize: 28672,
		Dependencies: []string{
			"so:libc.musl-x86_64.so.1",
			"so:libcrypto.so.1.1",
			"so:libssl.so.1.1",
		},
		Provides: []string{
			"cmd:ssl_client=1.35.0-r17",
		},
		Checksum:  "Q1KWJXawaNPiINHfdzCg/FrEmiAaU=",
		GitCommit: "2bf6ec48e526113f87216683cd341a78af5f0b3f",
		Files: []pkg.ApkFileRecord{
			{
				Path: "/usr",
			},
			{
				Path: "/usr/bin",
			},
			{
				Path:        "/usr/bin/ssl_client",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "755",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1C6qA8RFt5eagesbaqu4plc6Ctyc=",
				}),
			},
		},
	}
}

func libsslMetadata() pkg.ApkMetadata {
	return pkg.ApkMetadata{
		Package:       "libssl1.1",
		OriginPackage: "openssl",
		Maintainer:    "Timo Teras <timo.teras@iki.fi>",
		Version:       "1.1.1s-r0",
		Architecture:  "x86_64",
		URL:           "https://www.openssl.org/",
		Description:   "SSL shared libraries",
		Size:          213470,
		InstalledSize: 540672,
		Dependencies: []string{
			"so:libc.musl-x86_64.so.1",
			"so:libcrypto.so.1.1",
		},
		Provides: []string{
			"so:libssl.so.1.1=1.1",
		},
		Checksum:  "Q1dA1xCFDqKI3z/84yu4S77VxAU6g=",
		GitCommit: "46b66114372a5b408ec19d3a0a0faf4aa111a36f",
		Files: []pkg.ApkFileRecord{
			{
				Path: "/lib",
			},
			{
				Path:        "/lib/libssl.so.1.1",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "755",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q18j7n4cIb/ge1J3ty4Y8OtFzxGJ0=",
				}),
			},
			{
				Path: "/usr",
			},
			{
				Path: "/usr/lib",
			},
			{
				Path:        "/usr/lib/libssl.so.1.1",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "777",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q18j35pe3yp6HOgMih1wlGP1/mm2c=",
				}),
			},
		},
	}
}

func busyboxMetadata() pkg.ApkMetadata {
	return pkg.ApkMetadata{
		Package:       "busybox",
		OriginPackage: "busybox",
		Maintainer:    "Sören Tempel <soeren+alpine@soeren-tempel.net>",
		Version:       "1.35.0-r17",
		Architecture:  "x86_64",
		URL:           "https://busybox.net/",
		Description:   "Size optimized toolbox of many common UNIX utilities",
		Size:          507831,
		InstalledSize: 962560,
		Dependencies: []string{
			"so:libc.musl-x86_64.so.1",
		},
		Provides: []string{
			"/bin/sh",
			"cmd:busybox=1.35.0-r17",
			"cmd:sh=1.35.0-r17",
		},
		Checksum:  "Q1iZ+C2JJdBlm2KKtAOkSkM7zZegY=",
		GitCommit: "2bf6ec48e526113f87216683cd341a78af5f0b3f",
		Files: []pkg.ApkFileRecord{
			{
				Path: "/bin",
			},
			{
				Path:        "/bin/busybox",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "755",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1WUwBY0eOGgzgVxTZxJBZPyQUicI=",
				}),
			},
			{
				Path:        "/bin/sh",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "777",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1pcfTfDNEbNKQc2s1tia7da05M8Q=",
				}),
			},
			{
				Path: "/etc",
			},
			{
				Path: "/etc/securetty",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1mB95Hq2NUTZ599RDiSsj9w5FrOU=",
				}),
			},
			{
				Path: "/etc/udhcpd.conf",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1EgLFjj67ou3eMqp4m3r2ZjnQ7QU=",
				}),
			},
			{
				Path: "/etc/logrotate.d",
			},
			{
				Path: "/etc/logrotate.d/acpid",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1TylyCINVmnS+A/Tead4vZhE7Bks=",
				}),
			},
			{
				Path: "/etc/network",
			},
			{
				Path: "/etc/network/if-down.d",
			},
			{
				Path: "/etc/network/if-post-down.d",
			},
			{
				Path: "/etc/network/if-post-up.d",
			},
			{
				Path: "/etc/network/if-pre-down.d",
			},
			{
				Path: "/etc/network/if-pre-up.d",
			},
			{
				Path: "/etc/network/if-up.d",
			},
			{
				Path:        "/etc/network/if-up.d/dad",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "775",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1ORf+lPRKuYgdkBBcKoevR1t60Q4=",
				}),
			},
			{
				Path: "/sbin",
			},
			{
				Path:        "/tmp",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "1777",
			},
			{
				Path: "/usr",
			},
			{
				Path: "/usr/sbin",
			},
			{
				Path: "/usr/share",
			},
			{
				Path: "/usr/share/udhcpc",
			},
			{
				Path:        "/usr/share/udhcpc/default.script",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "755",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1t9vir/ZrX3nbSIYT9BDLWZenkVQ=",
				}),
			},
			{
				Path: "/var",
			},
			{
				Path: "/var/cache",
			},
			{
				Path: "/var/cache/misc",
			},
			{
				Path: "/var/lib",
			},
			{
				Path: "/var/lib/udhcpd",
			},
		},
	}
}

func muslMetadata() pkg.ApkMetadata {
	return pkg.ApkMetadata{
		Package:       "musl",
		OriginPackage: "musl",
		Maintainer:    "Timo Teräs <timo.teras@iki.fi>",
		Version:       "1.2.3-r1",
		Architecture:  "x86_64",
		URL:           "https://musl.libc.org/",
		Description:   "the musl c library (libc) implementation",
		Size:          383459,
		InstalledSize: 622592,
		Dependencies:  []string{},
		Provides: []string{
			"so:libc.musl-x86_64.so.1=1",
		},
		Checksum:  "Q14QhfC7ADTZ++cSoCC18jO47qnhQ=",
		GitCommit: "6711e7bdc190b184ec2db78d8ab5ebf06917ae78",
		Files: []pkg.ApkFileRecord{
			{
				Path: "/lib",
			},
			{
				Path:        "/lib/ld-musl-x86_64.so.1",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "755",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1qyxQz8gx3d2xv+3X9qfj8jvK/Y0=",
				}),
			},
			{
				Path:        "/lib/libc.musl-x86_64.so.1",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "777",
				Digest: (func(v file.Digest) *file.Digest { return &v })(file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q17yJ3JFNypA4mxhJJr0ou6CzsJVI=",
				}),
			},
		},
	}
}

func alpineBaseLayoutDataMetadata() pkg.ApkMetadata {
	return pkg.ApkMetadata{
		Package:       "alpine-baselayout-data",
		OriginPackage: "alpine-baselayout",
		Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
		Version:       "3.2.0-r23",
		Architecture:  "x86_64",
		URL:           "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
		Description:   "Alpine base dir structure and init scripts",
		Size:          11655,
		InstalledSize: 77824,
		Dependencies:  []string{},
		Provides:      []string{},
		Checksum:      "Q1d4HQ/Gyfw7NRD1qRvOgS6IzT2sI=",
		GitCommit:     "348653a9ba0701e8e968b3344e72313a9ef334e4",
		Files: []pkg.ApkFileRecord{
			{
				Path: "/etc",
			},
			{
				Path: "/etc/fstab",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q11Q7hNe8QpDS531guqCdrXBzoA/o=",
				},
			},
			{
				Path: "/etc/group",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q13K+olJg5ayzHSVNUkggZJXuB+9Y=",
				},
			},
			{
				Path: "/etc/hostname",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q16nVwYVXP/tChvUPdukVD2ifXOmc=",
				},
			},
			{
				Path: "/etc/hosts",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1BD6zJKZTRWyqGnPi4tSfd3krsMU=",
				},
			},
			{
				Path: "/etc/inittab",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1TsthbhW7QzWRe1E/NKwTOuD4pHc=",
				},
			},
			{
				Path: "/etc/modules",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1toogjUipHGcMgECgPJX64SwUT1M=",
				},
			},
			{
				Path:        "/etc/mtab",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "777",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1kiljhXXH1LlQroHsEJIkPZg2eiw=",
				},
			},
			{
				Path: "/etc/nsswitch.conf",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q19DBsMnv0R2fajaTjoTv0C91NOqo=",
				},
			},
			{
				Path: "/etc/passwd",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1TchuuLUfur0izvfZQZxgN/LJhB8=",
				},
			},
			{
				Path: "/etc/profile",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1F3DgXUP+jNZDknmQPPb5t9FSfDg=",
				},
			},
			{
				Path: "/etc/protocols",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1omKlp3vgGq2ZqYzyD/KHNdo8rDc=",
				},
			},
			{
				Path: "/etc/services",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q19WLCv5ItKg4MH7RWfNRh1I7byQc=",
				},
			},
			{
				Path:        "/etc/shadow",
				OwnerUID:    "0",
				OwnerGID:    "42",
				Permissions: "640",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1ltrPIAW2zHeDiajsex2Bdmq3uqA=",
				},
			},
			{
				Path: "/etc/shells",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1ojm2YdpCJ6B/apGDaZ/Sdb2xJkA=",
				},
			},
			{
				Path: "/etc/sysctl.conf",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q14upz3tfnNxZkIEsUhWn7Xoiw96g=",
				},
			},
		},
	}
}

func alpineBaseLayoutMetadata() pkg.ApkMetadata {
	return pkg.ApkMetadata{
		Package:       "alpine-baselayout",
		OriginPackage: "alpine-baselayout",
		Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
		Version:       "3.2.0-r23",
		Architecture:  "x86_64",
		URL:           "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
		Description:   "Alpine base dir structure and init scripts",
		Size:          11136,
		InstalledSize: 348160,
		Dependencies: []string{
			"alpine-baselayout-data=3.2.0-r23",
			"/bin/sh",
			"so:libc.musl-x86_64.so.1",
		},
		Provides: []string{
			"cmd:mkmntdirs=3.2.0-r23",
		},
		Checksum:  "Q19UI7UxyiUywG6aew9c3lCBPshsE=",
		GitCommit: "348653a9ba0701e8e968b3344e72313a9ef334e4",
		Files: []pkg.ApkFileRecord{
			{
				Path: "/dev",
			},
			{
				Path: "/dev/pts",
			},
			{
				Path: "/dev/shm",
			},
			{
				Path: "/etc",
			},
			{
				Path: "/etc/motd",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1XmduVVNURHQ27TvYp1Lr5TMtFcA=",
				},
			},
			{
				Path: "/etc/apk",
			},
			{
				Path: "/etc/conf.d",
			},
			{
				Path: "/etc/crontabs",
			},
			{
				Path:        "/etc/crontabs/root",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "600",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1vfk1apUWI4yLJGhhNRd0kJixfvY=",
				},
			},
			{
				Path: "/etc/init.d",
			},
			{
				Path: "/etc/modprobe.d",
			},
			{
				Path: "/etc/modprobe.d/aliases.conf",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1WUbh6TBYNVK7e4Y+uUvLs/7viqk=",
				},
			},
			{
				Path: "/etc/modprobe.d/blacklist.conf",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q14TdgFHkTdt3uQC+NBtrntOnm9n4=",
				},
			},
			{
				Path: "/etc/modprobe.d/i386.conf",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1pnay/njn6ol9cCssL7KiZZ8etlc=",
				},
			},
			{
				Path: "/etc/modprobe.d/kms.conf",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1ynbLn3GYDpvajba/ldp1niayeog=",
				},
			},
			{
				Path: "/etc/modules-load.d",
			},
			{
				Path: "/etc/network",
			},
			{
				Path: "/etc/network/if-down.d",
			},
			{
				Path: "/etc/network/if-post-down.d",
			},
			{
				Path: "/etc/network/if-pre-up.d",
			},
			{
				Path: "/etc/network/if-up.d",
			},
			{
				Path: "/etc/opt",
			},
			{
				Path: "/etc/periodic",
			},
			{
				Path: "/etc/periodic/15min",
			},
			{
				Path: "/etc/periodic/daily",
			},
			{
				Path: "/etc/periodic/hourly",
			},
			{
				Path: "/etc/periodic/monthly",
			},
			{
				Path: "/etc/periodic/weekly",
			},
			{
				Path: "/etc/profile.d",
			},
			{
				Path: "/etc/profile.d/README",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q135OWsCzzvnB2fmFx62kbqm1Ax1k=",
				},
			},
			{
				Path: "/etc/profile.d/color_prompt.sh.disabled",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q11XM9mde1Z29tWMGaOkeovD/m4uU=",
				},
			},
			{
				Path: "/etc/profile.d/locale.sh",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1S8j+WW71mWxfVy8ythqU7HUVoBw=",
				},
			},
			{
				Path: "/etc/sysctl.d",
			},
			{
				Path: "/home",
			},
			{
				Path: "/lib",
			},
			{
				Path: "/lib/firmware",
			},
			{
				Path: "/lib/mdev",
			},
			{
				Path: "/lib/modules-load.d",
			},
			{
				Path: "/lib/sysctl.d",
			},
			{
				Path: "/lib/sysctl.d/00-alpine.conf",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1HpElzW1xEgmKfERtTy7oommnq6c=",
				},
			},
			{
				Path: "/media",
			},
			{
				Path: "/media/cdrom",
			},
			{
				Path: "/media/floppy",
			},
			{
				Path: "/media/usb",
			},
			{
				Path: "/mnt",
			},
			{
				Path: "/opt",
			},
			{
				Path: "/proc",
			},
			{
				Path:        "/root",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "700",
			},
			{
				Path: "/run",
			},
			{
				Path: "/sbin",
			},
			{
				Path:        "/sbin/mkmntdirs",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "755",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1+f8Hjd+dkHS03O6ZZaIw7mb8nLM=",
				},
			},
			{
				Path: "/srv",
			},
			{
				Path: "/sys",
			},
			{
				Path:        "/tmp",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "1777",
			},
			{
				Path: "/usr",
			},
			{
				Path: "/usr/lib",
			},
			{
				Path: "/usr/lib/modules-load.d",
			},
			{
				Path: "/usr/local",
			},
			{
				Path: "/usr/local/bin",
			},
			{
				Path: "/usr/local/lib",
			},
			{
				Path: "/usr/local/share",
			},
			{
				Path: "/usr/sbin",
			},
			{
				Path: "/usr/share",
			},
			{
				Path: "/usr/share/man",
			},
			{
				Path: "/usr/share/misc",
			},
			{
				Path: "/var",
			},
			{
				Path:        "/var/run",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "777",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q11/SNZz/8cK2dSKK+cJpVrZIuF4Q=",
				},
			},
			{
				Path: "/var/cache",
			},
			{
				Path: "/var/cache/misc",
			},
			{
				Path:        "/var/empty",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "555",
			},
			{
				Path: "/var/lib",
			},
			{
				Path: "/var/lib/misc",
			},
			{
				Path: "/var/local",
			},
			{
				Path: "/var/lock",
			},
			{
				Path: "/var/lock/subsys",
			},
			{
				Path: "/var/log",
			},
			{
				Path: "/var/mail",
			},
			{
				Path: "/var/opt",
			},
			{
				Path: "/var/spool",
			},
			{
				Path:        "/var/spool/mail",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "777",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1dzbdazYZA2nTzSIG3YyNw7d4Juc=",
				},
			},
			{
				Path: "/var/spool/cron",
			},
			{
				Path:        "/var/spool/cron/crontabs",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "777",
				Digest: &file.Digest{
					Algorithm: "'Q1'+base64(sha1)",
					Value:     "Q1OFZt+ZMp7j0Gny0rqSKuWJyqYmA=",
				},
			},
			{
				Path:        "/var/tmp",
				OwnerUID:    "0",
				OwnerGID:    "0",
				Permissions: "1777",
			},
		},
	}
}
