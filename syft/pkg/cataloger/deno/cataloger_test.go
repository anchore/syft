package deno

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_DenoCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain deno.lock files",
			fixture: "test-fixtures",
			expected: []string{
				"corrupt/deno.lock",
				"deno.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewLockCataloger())
		})
	}
}

func Test_DenoCataloger(t *testing.T) {
	locationSet := file.NewLocationSet(file.NewLocation("deno.lock"))

	expectedPkgs := []pkg.Package{
		{
			Name:      "@std/bytes",
			Version:   "1.0.2",
			FoundBy:   "deno-lock-cataloger",
			PURL:      "pkg:jsr/%40std/bytes@1.0.2",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.JsrPkg,
			Metadata: pkg.DenoLockEntry{
				Integrity: "fbdee322bbd8c599a6af186a1603b3355e59a5fb1baa139f8f4c3c9a1b3e3d57",
			},
		},
		{
			Name:      "@std/encoding",
			Version:   "1.0.5",
			FoundBy:   "deno-lock-cataloger",
			PURL:      "pkg:jsr/%40std/encoding@1.0.5",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.JsrPkg,
			Metadata: pkg.DenoLockEntry{
				Integrity:    "ecf363d4fc25bd85bd915ff6733a7e79b67e0e7806334af15f4645c569fefc04",
				Dependencies: []string{"jsr:@std/bytes@^1.0.0"},
			},
		},
		{
			Name:      "chalk",
			Version:   "5.3.0",
			FoundBy:   "deno-lock-cataloger",
			PURL:      "pkg:npm/chalk@5.3.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.NpmPkg,
			Metadata: pkg.NpmPackageLockEntry{
				Integrity: "sha512-dLitG79d+GV1Nb/VYcCDFivJeK1hiukt9QjRNVOsUtTy1rR1YJsmpGGTZ3qJos+uw7WmWF4wUwBd9jxjocFC2w==",
			},
		},
		{
			Name:      "deno.land/std",
			Version:   "0.140.0",
			FoundBy:   "deno-lock-cataloger",
			PURL:      "pkg:deno/deno.land%2Fstd@0.140.0",
			Locations: locationSet,
			Language:  pkg.JavaScript,
			Type:      pkg.JsrPkg,
			Metadata: pkg.DenoRemoteLockEntry{
				URL:       "https://deno.land/std@0.140.0/path/mod.ts",
				Integrity: "d3e68d0abb393fb0bf94a6d07c46ec31dc755b544b13144dee931d8d5f06a52d",
			},
		},
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures").
		Expects(expectedPkgs, nil).
		TestCataloger(t, NewLockCataloger())
}
