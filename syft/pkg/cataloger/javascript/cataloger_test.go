package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_JavascriptCataloger(t *testing.T) {
	locationSet := file.NewLocationSet(file.NewLocation("package-lock.json"))
	expectedPkgs := []pkg.Package{
		{
			Name:      "@actions/core",
			Version:   "1.6.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/%40actions/core@1.6.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromLocations("MIT", file.NewLocation("package-lock.json")),
			),
			Metadata: pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/@actions/core/-/core-1.6.0.tgz", Integrity: "sha512-NB1UAZomZlCV/LmJqkLhNTqtKfFXJZAUPcfl/zqG7EfsQdeUJtaWO98SGbuQ3pydJ3fHl2CvI/51OKYlCYYcaw=="},
		},
		{
			Name:      "ansi-regex",
			Version:   "3.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/ansi-regex@3.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/ansi-regex/-/ansi-regex-3.0.0.tgz", Integrity: "sha1-7QMXwyIGT3lGbAKWa922Bas32Zg="},
		},
		{
			Name:      "cowsay",
			Version:   "1.4.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/cowsay@1.4.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Licenses: pkg.NewLicenseSet(
				pkg.NewLicenseFromLocations("MIT", file.NewLocation("package-lock.json")),
			),
			Metadata: pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/cowsay/-/cowsay-1.4.0.tgz", Integrity: "sha512-rdg5k5PsHFVJheO/pmE3aDg2rUDDTfPJau6yYkZYlHFktUz+UxbE+IgnUAEyyCyv4noL5ltxXD0gZzmHPCy/9g=="},
		},
		{
			Name:      "get-stdin",
			Version:   "5.0.1",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/get-stdin@5.0.1",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/get-stdin/-/get-stdin-5.0.1.tgz", Integrity: "sha1-Ei4WFZHiH/TFJTAwVpPyDmOTo5g="},
		},
		{
			Name:      "is-fullwidth-code-point",
			Version:   "2.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/is-fullwidth-code-point@2.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/is-fullwidth-code-point/-/is-fullwidth-code-point-2.0.0.tgz", Integrity: "sha1-o7MKXE8ZkYMWeqq5O+764937ZU8="},
		},
		{
			Name:      "minimist",
			Version:   "0.0.10",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/minimist@0.0.10",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/minimist/-/minimist-0.0.10.tgz", Integrity: "sha1-3j+YVD2/lggr5IrRoMfNqDYwHc8="},
		},
		{
			Name:      "optimist",
			Version:   "0.6.1",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/optimist@0.6.1",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/optimist/-/optimist-0.6.1.tgz", Integrity: "sha1-2j6nRob6IaGaERwybpDrFaAZZoY="},
		},
		{
			Name:      "string-width",
			Version:   "2.1.1",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/string-width@2.1.1",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/string-width/-/string-width-2.1.1.tgz", Integrity: "sha512-nOqH59deCq9SRHlxq1Aw85Jnt4w6KvLKqWVik6oA9ZklXLNIOlqg4F2yrT1MVaTjAqvVwdfeZ7w7aCvJD7ugkw=="},
		},
		{
			Name:      "strip-ansi",
			Version:   "4.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/strip-ansi@4.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/strip-ansi/-/strip-ansi-4.0.0.tgz", Integrity: "sha1-qEeQIusaw2iocTibY1JixQXuNo8="},
		},
		{
			Name:      "strip-eof",
			Version:   "1.0.0",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/strip-eof@1.0.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/strip-eof/-/strip-eof-1.0.0.tgz", Integrity: "sha1-u0P/VZim6wXYm1n80SnJgzE2Br8="},
		},
		{
			Name:      "wordwrap",
			Version:   "0.0.3",
			FoundBy:   "javascript-lock-cataloger",
			PURL:      "pkg:npm/wordwrap@0.0.3",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata:  pkg.NpmPackageLockEntry{Resolved: "https://registry.npmjs.org/wordwrap/-/wordwrap-0.0.3.tgz", Integrity: "sha1-o9XabNXAvAAI03I0u68b7WMFkQc="},
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-lock").
		Expects(expectedPkgs, nil).
		TestCataloger(t, NewLockCataloger(CatalogerConfig{}))

}

func Test_PackageCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain package files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/package.json",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewPackageCataloger())
		})
	}
}

func Test_LockCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain package files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/package-lock.json",
				"src/pnpm-lock.yaml",
				"src/yarn.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewLockCataloger(CatalogerConfig{}))
		})
	}
}
