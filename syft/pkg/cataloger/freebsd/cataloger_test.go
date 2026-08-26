package freebsd

import (
	"context"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_DBCataloger_Globs(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "testdata/glob-paths").
		ExpectsResolverContentQueries([]string{
			"var/db/pkg/local.sqlite",
		}).
		TestCataloger(t, NewDBCataloger())
}

func Test_DBCataloger(t *testing.T) {
	dbLocation := file.NewLocation("testdata/local.sqlite")
	locations := file.NewLocationSet(dbLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	curlPkg := pkg.Package{
		Name:      "curl",
		Version:   "8.9.1",
		Type:      pkg.FreeBSDPkg,
		Locations: locations,
		FoundBy:   "freebsd-db-cataloger",
		PURL:      "pkg:freebsd/curl@8.9.1?arch=FreeBSD%3A14%3Aamd64&origin=www%2Fcurl",
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(context.Background(), dbLocation, "MIT", "ISC")...),
		Metadata: pkg.FreeBSDPkgDBEntry{
			Origin:         "www/curl",
			Name:           "curl",
			Version:        "8.9.1",
			Comment:        "Command line tool and library for transferring data with URLs",
			Description:    "cURL is a command line tool for transferring data specified with URL syntax.",
			Arch:           "FreeBSD:14:amd64",
			Maintainer:     "jmcneill@FreeBSD.org",
			WWW:            "https://curl.se/",
			Prefix:         "/usr/local",
			FlatSize:       3345871,
			Automatic:      false,
			Locked:         false,
			LicenseLogic:   "or",
			ManifestDigest: "1220c1f6a5b1e6f3f2a3f9c9e8d7b6a5f4e3d2c1b0a9887766554433221100aabb",
			Vital:          false,
			Licenses:       []string{"MIT", "ISC"},
			Files: []pkg.FreeBSDFileRecord{
				{
					Path:      "/usr/local/bin/curl",
					Digest:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					UserName:  "root",
					GroupName: "wheel",
				},
				{
					Path:      "/usr/local/share/doc/curl/FAQ",
					Digest:    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					UserName:  "root",
					GroupName: "wheel",
				},
			},
		},
	}
	curlPkg.SetID()

	libcurlPkg := pkg.Package{
		Name:      "libcurl",
		Version:   "8.9.1",
		Type:      pkg.FreeBSDPkg,
		Locations: locations,
		FoundBy:   "freebsd-db-cataloger",
		PURL:      "pkg:freebsd/libcurl@8.9.1?arch=FreeBSD%3A14%3Aamd64&origin=ftp%2Fcurl",
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(context.Background(), dbLocation, "MIT", "ISC")...),
		Metadata: pkg.FreeBSDPkgDBEntry{
			Origin:         "ftp/curl",
			Name:           "libcurl",
			Version:        "8.9.1",
			Comment:        "Multiprotocol file transfer library",
			Description:    "libcurl is a free and easy-to-use client-side URL transfer library.",
			Arch:           "FreeBSD:14:amd64",
			Maintainer:     "jmcneill@FreeBSD.org",
			WWW:            "https://curl.se/",
			Prefix:         "/usr/local",
			FlatSize:       1958732,
			Automatic:      true,
			Locked:         false,
			LicenseLogic:   "or",
			ManifestDigest: "2331d2073f2e1e4a1f3b4a5c6d7e8f9001122334455667788990011223344556",
			Vital:          false,
			Licenses:       []string{"MIT", "ISC"},
			Files: []pkg.FreeBSDFileRecord{
				{
					Path:      "/usr/local/lib/libcurl.so.4",
					Digest:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
					UserName:  "root",
					GroupName: "wheel",
				},
				{
					Path:      "/usr/local/include/curl/curl.h",
					Digest:    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
					UserName:  "root",
					GroupName: "wheel",
				},
			},
		},
	}
	libcurlPkg.SetID()

	caRootNssPkg := pkg.Package{
		Name:      "ca_root_nss",
		Version:   "3.104",
		Type:      pkg.FreeBSDPkg,
		Locations: locations,
		FoundBy:   "freebsd-db-cataloger",
		PURL:      "pkg:freebsd/ca_root_nss@3.104?arch=FreeBSD%3A14%3A%2A&origin=security%2Fca_root_nss",
		Licenses:  pkg.NewLicenseSet(pkg.NewLicensesFromLocationWithContext(context.Background(), dbLocation, "MPL-2.0")...),
		Metadata: pkg.FreeBSDPkgDBEntry{
			Origin:         "security/ca_root_nss",
			Name:           "ca_root_nss",
			Version:        "3.104",
			Comment:        "Root certificate bundle from the Mozilla Project",
			Description:    "This package contains the root certificate bundle extracted from the Mozilla NSS.",
			Arch:           "FreeBSD:14:*",
			Maintainer:     "martin@FreeBSD.org",
			WWW:            "https://wiki.mozilla.org/CA",
			Prefix:         "/usr/local",
			FlatSize:       313842,
			Automatic:      true,
			Locked:         false,
			LicenseLogic:   "single",
			ManifestDigest: "3442e3184f3f2f5b2f4c5b6d7e8f900112233445566778899001122334455667",
			Vital:          false,
			Licenses:       []string{"MPL-2.0"},
			Files: []pkg.FreeBSDFileRecord{
				{
					Path:      "/usr/local/share/certs/ca-root-nss.crt",
					Digest:    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
					UserName:  "root",
					GroupName: "wheel",
				},
			},
		},
	}
	caRootNssPkg.SetID()

	expectedPkgs := []pkg.Package{curlPkg, libcurlPkg, caRootNssPkg}

	pkgtest.NewCatalogTester().
		FromFile(t, "testdata/local.sqlite").
		Expects(expectedPkgs, nil).
		TestParser(t, parsePkgDB)
}
