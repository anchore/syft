package alpine

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestApkDBCataloger(t *testing.T) {
	dbLocation := file.NewLocation("lib/apk/db/installed")

	bashPkg := pkg.Package{
		Name:    "bash",
		Version: "5.2.21-r0",
		Type:    pkg.ApkPkg,
		FoundBy: "apk-db-cataloger",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("GPL-3.0-or-later", dbLocation),
		),
		Locations: file.NewLocationSet(dbLocation),
		Metadata: pkg.ApkDBEntry{
			Package:       "bash",
			OriginPackage: "bash",
			Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
			Version:       "5.2.21-r0",
			Architecture:  "x86_64",
			URL:           "https://www.gnu.org/software/bash/bash.html",
			Description:   "The GNU Bourne Again shell",
			Size:          448728,
			InstalledSize: 1396736,
			Dependencies: []string{
				"/bin/sh", "so:libc.musl-x86_64.so.1", "so:libreadline.so.8",
			},
			Provides: []string{
				"cmd:bash=5.2.21-r0",
			},
			// note: files not provided and not under test
		},
	}

	busyboxBinshPkg := pkg.Package{
		Name:    "busybox-binsh",
		Version: "1.36.1-r15",
		Type:    pkg.ApkPkg,
		FoundBy: "apk-db-cataloger",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("GPL-2.0-only", dbLocation),
		),
		Locations: file.NewLocationSet(dbLocation),
		Metadata: pkg.ApkDBEntry{
			Package:       "busybox-binsh",
			OriginPackage: "busybox",
			Maintainer:    "Sören Tempel <soeren+alpine@soeren-tempel.net>",
			Version:       "1.36.1-r15",
			Architecture:  "x86_64",
			URL:           "https://busybox.net/",
			Description:   "busybox ash /bin/sh",
			Size:          1543,
			InstalledSize: 8192,
			Dependencies: []string{
				"busybox=1.36.1-r15",
			},
			Provides: []string{
				"/bin/sh", "cmd:sh=1.36.1-r15",
			},
			// note: files not provided and not under test
		},
	}

	muslPkg := pkg.Package{
		Name:    "musl",
		Version: "1.2.4_git20230717-r4",
		Type:    pkg.ApkPkg,
		FoundBy: "apk-db-cataloger",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("MIT", dbLocation),
		),
		Locations: file.NewLocationSet(dbLocation),
		Metadata: pkg.ApkDBEntry{
			Package:       "musl",
			OriginPackage: "musl",
			Maintainer:    "Timo Teräs <timo.teras@iki.fi>",
			Version:       "1.2.4_git20230717-r4",
			Architecture:  "x86_64",
			URL:           "https://musl.libc.org/",
			Description:   "the musl c library (libc) implementation",
			Size:          407278,
			InstalledSize: 667648,
			Dependencies:  []string{},
			Provides: []string{
				"so:libc.musl-x86_64.so.1=1",
			},
			// note: files not provided and not under test
		},
	}

	readlinePkg := pkg.Package{
		Name:    "readline",
		Version: "8.2.1-r2",
		Type:    pkg.ApkPkg,
		FoundBy: "apk-db-cataloger",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("GPL-2.0-or-later", dbLocation),
		),
		Locations: file.NewLocationSet(dbLocation),
		Metadata: pkg.ApkDBEntry{
			Package:       "readline",
			OriginPackage: "readline",
			Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
			Version:       "8.2.1-r2",
			Architecture:  "x86_64",
			URL:           "https://tiswww.cwru.edu/php/chet/readline/rltop.html",
			Description:   "GNU readline library",
			Size:          119878,
			InstalledSize: 303104,
			Dependencies: []string{
				"so:libc.musl-x86_64.so.1", "so:libncursesw.so.6",
			},
			Provides: []string{
				"so:libreadline.so.8=8.2",
			},
			// note: files not provided and not under test
		},
	}

	expectedPkgs := []pkg.Package{
		bashPkg,
		busyboxBinshPkg,
		muslPkg,
		readlinePkg,
	}

	// # apk info --depends bash
	//   bash-5.2.21-r0 depends on:
	//   /bin/sh
	//   so:libc.musl-x86_64.so.1
	//   so:libreadline.so.8
	//
	// # apk info --who-owns /bin/sh
	//   /bin/sh is owned by busybox-binsh-1.36.1-r15
	//
	// # find / | grep musl
	//   /lib/ld-musl-x86_64.so.1
	//   /lib/libc.musl-x86_64.so.1
	//
	// # apk info --who-owns '/lib/libc.musl-x86_64.so.1'
	//   /lib/libc.musl-x86_64.so.1 is owned by musl-1.2.4_git20230717-r4
	//
	// # find / | grep libreadline
	//   /usr/lib/libreadline.so.8.2
	//   /usr/lib/libreadline.so.8
	//
	// # apk info --who-owns '/usr/lib/libreadline.so.8'
	//   /usr/lib/libreadline.so.8 is owned by readline-8.2.1-r2

	expectedRelationships := []artifact.Relationship{
		{
			From: busyboxBinshPkg,
			To:   bashPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: readlinePkg,
			To:   bashPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: muslPkg,
			To:   readlinePkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: muslPkg,
			To:   bashPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/multiple-1").
		WithCompareOptions(cmpopts.IgnoreFields(pkg.ApkDBEntry{}, "Files", "GitCommit", "Checksum")).
		Expects(expectedPkgs, expectedRelationships).
		TestCataloger(t, NewDBCataloger())

}

func Test_corruptDb(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/corrupt").
		WithCompareOptions(cmpopts.IgnoreFields(pkg.ApkDBEntry{}, "Files", "GitCommit", "Checksum")).
		WithError().
		TestCataloger(t, NewDBCataloger())
}

func TestCatalogerDependencyTree(t *testing.T) {
	assertion := func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		expected := map[string][]string{
			"alpine-baselayout": {"busybox", "alpine-baselayout-data", "musl"},
			"apk-tools":         {"ca-certificates-bundle", "musl", "libcrypto1.1", "libssl1.1", "zlib"},
			"busybox":           {"musl"},
			"libc-utils":        {"musl-utils"},
			"libcrypto1.1":      {"musl"},
			"libssl1.1":         {"musl", "libcrypto1.1"},
			"musl-utils":        {"scanelf", "musl"},
			"scanelf":           {"musl"},
			"ssl_client":        {"musl", "libcrypto1.1", "libssl1.1"},
			"zlib":              {"musl"},
		}
		pkgsByID := make(map[artifact.ID]pkg.Package)
		for _, p := range pkgs {
			p.SetID()
			pkgsByID[p.ID()] = p
		}

		actualDependencies := make(map[string][]string)

		for _, r := range relationships {
			switch r.Type {
			case artifact.DependencyOfRelationship:
				to := pkgsByID[r.To.ID()]
				from := pkgsByID[r.From.ID()]
				actualDependencies[to.Name] = append(actualDependencies[to.Name], from.Name)
			default:
				t.Fatalf("unexpected relationship type: %+v", r.Type)
			}
		}

		if d := cmp.Diff(expected, actualDependencies); d != "" {
			t.Fail()
			t.Log(d)
		}
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/multiple-2").
		ExpectsAssertion(assertion).
		TestCataloger(t, NewDBCataloger())

}

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:     "obtain DB files",
			fixture:  "test-fixtures/glob-paths",
			expected: []string{"lib/apk/db/installed"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				IgnoreUnfulfilledPathResponses("etc/apk/repositories").
				TestCataloger(t, NewDBCataloger())
		})
	}
}
