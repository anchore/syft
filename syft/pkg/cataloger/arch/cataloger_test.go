package arch

import (
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestAlpmUnknowns(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/installed").
		WithCompareOptions(cmpopts.IgnoreFields(pkg.AlpmFileRecord{}, "Time")).
		WithError().
		TestCataloger(t, NewDBCataloger())
}

func TestAlpmCataloger(t *testing.T) {
	gmpDbLocation := file.NewLocation("var/lib/pacman/local/gmp-6.2.1-2/desc")
	treeSitterDbLocation := file.NewLocation("var/lib/pacman/local/tree-sitter-0.22.6-1/desc")
	emacsDbLocation := file.NewLocation("var/lib/pacman/local/emacs-29.3-3/desc")
	fuzzyDbLocation := file.NewLocation("var/lib/pacman/local/fuzzy-1.2-3/desc")
	madeupDbLocation := file.NewLocation("var/lib/pacman/local/madeup-20.30-4/desc")

	treeSitterPkg := pkg.Package{
		Name:    "tree-sitter",
		Version: "0.22.6-1",
		Type:    pkg.AlpmPkg,
		FoundBy: "alpm-db-cataloger",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("MIT", treeSitterDbLocation),
		),
		Locations: file.NewLocationSet(treeSitterDbLocation),
		Metadata: pkg.AlpmDBEntry{
			BasePackage:  "tree-sitter",
			Package:      "tree-sitter",
			Version:      "0.22.6-1",
			Description:  "Incremental parsing library",
			Architecture: "x86_64",
			Size:         223539,
			Packager:     "Daniel M. Capella <polyzen@archlinux.org>",
			URL:          "https://github.com/tree-sitter/tree-sitter",
			Validation:   "pgp",
			Reason:       1,
			Files:        []pkg.AlpmFileRecord{},
			Backup:       []pkg.AlpmFileRecord{},
			Provides:     []string{"libtree-sitter.so=0-64"},
		},
	}

	emacsPkg := pkg.Package{
		Name:    "emacs",
		Version: "29.3-3",
		Type:    pkg.AlpmPkg,
		FoundBy: "alpm-db-cataloger",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("GPL3", emacsDbLocation),
		),
		Locations: file.NewLocationSet(emacsDbLocation),
		Metadata: pkg.AlpmDBEntry{
			BasePackage:  "emacs",
			Package:      "emacs",
			Version:      "29.3-3",
			Description:  "The extensible, customizable, self-documenting real-time display editor",
			Architecture: "x86_64",
			Size:         126427862,
			Packager:     "Frederik Schwan <freswa@archlinux.org>",
			URL:          "https://www.gnu.org/software/emacs/emacs.html",
			Validation:   "pgp",
			Files:        []pkg.AlpmFileRecord{},
			Backup:       []pkg.AlpmFileRecord{},
			Depends:      []string{"libtree-sitter.so=0-64"},
		},
	}

	fuzzyPkg := pkg.Package{
		Name:    "fuzzy",
		Version: "1.2-3",
		Type:    pkg.AlpmPkg,
		FoundBy: "alpm-db-cataloger",
		Locations: file.NewLocationSet(
			fuzzyDbLocation,
			file.NewLocation("var/lib/pacman/local/fuzzy-1.2-3/files"),
		),
		Metadata: pkg.AlpmDBEntry{
			Package: "fuzzy",
			Version: "1.2-3",
			Files:   []pkg.AlpmFileRecord{},
			Backup: []pkg.AlpmFileRecord{
				{
					Path: "/etc/fuzzy.conf",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "79fce043df7dfc676ae5ecb903762d8b"},
					},
				},
			},
			Depends: []string{"tree-sitter"},
		},
	}

	madeupPkg := pkg.Package{
		Name:      "madeup",
		Version:   "20.30-4",
		Type:      pkg.AlpmPkg,
		FoundBy:   "alpm-db-cataloger",
		Locations: file.NewLocationSet(madeupDbLocation),
		Metadata: pkg.AlpmDBEntry{
			Package: "madeup",
			Version: "20.30-4",
			Files:   []pkg.AlpmFileRecord{},
			Backup:  []pkg.AlpmFileRecord{},
			Depends: []string{"libtree-sitter.so"},
		},
	}

	gmpPkg := pkg.Package{
		Name:    "gmp",
		Version: "6.2.1-2",
		Type:    pkg.AlpmPkg,
		FoundBy: "alpm-db-cataloger",
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocations("LGPL3", gmpDbLocation),
			pkg.NewLicenseFromLocations("GPL", gmpDbLocation),
		),
		Locations: file.NewLocationSet(
			gmpDbLocation,
			file.NewLocation("var/lib/pacman/local/gmp-6.2.1-2/files"),
			file.NewLocation("var/lib/pacman/local/gmp-6.2.1-2/mtree"),
		),
		Metadata: pkg.AlpmDBEntry{
			BasePackage:  "gmp",
			Package:      "gmp",
			Version:      "6.2.1-2",
			Description:  "A free library for arbitrary precision arithmetic",
			Architecture: "x86_64",
			Size:         1044438,
			Packager:     "Antonio Rojas <arojas@archlinux.org>",
			URL:          "https://gmplib.org/",
			Validation:   "pgp",
			Reason:       1,
			Depends:      []string{"gcc-libs", "sh", "libtree-sitter.so=1-64"},
			Files: []pkg.AlpmFileRecord{
				{
					Path:    "/usr",
					Type:    "dir",
					Digests: []file.Digest{},
				},
				{
					Path:    "/usr/include",
					Type:    "dir",
					Digests: []file.Digest{},
				},
				{
					Path: "/usr/include/gmp.h",
					Size: "84140",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "76595f70565c72550eb520809bf86856"},
						{Algorithm: "sha256", Value: "91a614b9202453153fe3b7512d15e89659108b93ce8841c8e13789eb85da9e3a"},
					},
				},
				{
					Path: "/usr/include/gmpxx.h",
					Size: "129113",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "ea3d21de4bcf7c696799c5c55dd3655b"},
						{Algorithm: "sha256", Value: "0011ae411a0bc1030e07d968b32fdc1343f5ac2a17b7d28f493e7976dde2ac82"},
					},
				},
				{
					Path:    "/usr/lib",
					Type:    "dir",
					Digests: []file.Digest{},
				},
				{
					Path:    "/usr/lib/libgmp.so",
					Type:    "link",
					Link:    "libgmp.so.10.4.1",
					Digests: []file.Digest{},
				},
				{
					Path:    "/usr/lib/libgmp.so.10",
					Type:    "link",
					Link:    "libgmp.so.10.4.1",
					Digests: []file.Digest{},
				},
				{
					Path: "/usr/lib/libgmp.so.10.4.1",
					Size: "663224",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "d6d03eadacdd9048d5b2adf577e9d722"},
						{Algorithm: "sha256", Value: "39898bd3d8d6785222432fa8b8aef7ce3b7e5bbfc66a52b7c0da09bed4adbe6a"},
					},
				},
				{
					Path:    "/usr/lib/libgmpxx.so",
					Type:    "link",
					Link:    "libgmpxx.so.4.6.1",
					Digests: []file.Digest{},
				},
				{
					Path:    "/usr/lib/libgmpxx.so.4",
					Type:    "link",
					Link:    "libgmpxx.so.4.6.1",
					Digests: []file.Digest{},
				},
				{
					Path: "/usr/lib/libgmpxx.so.4.6.1",
					Size: "30680",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "dd5f0c4d635fa599fa7f4339c0e8814d"},
						{Algorithm: "sha256", Value: "0ef67cbde4841f58d2e4b41f59425eb87c9eeaf4e649c060b326342c53bedbec"},
					},
				},
				{
					Path:    "/usr/lib/pkgconfig",
					Type:    "dir",
					Digests: []file.Digest{},
				},
				{
					Path: "/usr/lib/pkgconfig/gmp.pc",
					Size: "245",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "a91a9f1b66218cb77b9cd2cdf341756d"},
						{Algorithm: "sha256", Value: "4e9de547a48c4e443781e9fa702a1ec5a23ee28b4bc520306cff2541a855be37"},
					},
				},
				{
					Path: "/usr/lib/pkgconfig/gmpxx.pc",
					Size: "280",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "8c0f54e987934352177a6a30a811b001"},
						{Algorithm: "sha256", Value: "fc5dbfbe75977057ba50953d94b9daecf696c9fdfe5b94692b832b44ecca871b"},
					},
				},
				{
					Path:    "/usr/share",
					Type:    "dir",
					Digests: []file.Digest{},
				},
				{
					Path:    "/usr/share/info",
					Type:    "dir",
					Digests: []file.Digest{},
				},
				{
					Path: "/usr/share/info/gmp.info-1.gz",
					Size: "85892",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "63304d4d2f0247fb8a999fae66a81c19"},
						{Algorithm: "sha256", Value: "86288c1531a2789db5da8b9838b5cde4db07bda230ae11eba23a1f33698bd14e"},
					},
				},
				{
					Path: "/usr/share/info/gmp.info-2.gz",
					Size: "48484",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "4bb0dadec416d305232cac6eae712ff7"},
						{Algorithm: "sha256", Value: "b7443c1b529588d98a074266087f79b595657ac7274191c34b10a9ceedfa950e"},
					},
				},
				{
					Path: "/usr/share/info/gmp.info.gz",
					Size: "2380",
					Digests: []file.Digest{
						{Algorithm: "md5", Value: "cf6880fb0d862ee1da0d13c3831b5720"},
						{Algorithm: "sha256", Value: "a13c8eecda3f3e5ad1e09773e47a9686f07d9d494eaddf326f3696bbef1548fd"},
					},
				},
			},
			Backup: []pkg.AlpmFileRecord{},
		},
	}

	expectedPkgs := []pkg.Package{
		treeSitterPkg,
		emacsPkg,
		fuzzyPkg,
		madeupPkg,
		gmpPkg,
	}

	expectedRelationships := []artifact.Relationship{
		{ // exact spec lookup
			From: treeSitterPkg,
			To:   emacsPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{ // package name lookup
			From: treeSitterPkg,
			To:   fuzzyPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{ // library name lookup
			From: treeSitterPkg,
			To:   madeupPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/installed").
		WithCompareOptions(cmpopts.IgnoreFields(pkg.AlpmFileRecord{}, "Time")).
		Expects(expectedPkgs, expectedRelationships).
		TestCataloger(t, NewDBCataloger())

}

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain description files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"var/lib/pacman/local/base-1.0/desc",
				"var/lib/pacman/local/dive-0.10.0/desc",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				IgnoreUnfulfilledPathResponses("var/lib/pacman/local/base-1.0/mtree", "var/lib/pacman/local/dive-0.10.0/mtree").
				TestCataloger(t, NewDBCataloger())
		})
	}
}
