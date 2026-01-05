package deno

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseDenoLock(t *testing.T) {
	var expectedRelationships []artifact.Relationship
	fixture := "test-fixtures/deno.lock"

	expectedPkgs := []pkg.Package{
		{
			Name:     "@std/bytes",
			Version:  "1.0.2",
			PURL:     "pkg:jsr/%40std/bytes@1.0.2",
			Language: pkg.JavaScript,
			Type:     pkg.JsrPkg,
			Metadata: pkg.DenoLockEntry{
				Integrity: "fbdee322bbd8c599a6af186a1603b3355e59a5fb1baa139f8f4c3c9a1b3e3d57",
			},
		},
		{
			Name:     "@std/encoding",
			Version:  "1.0.5",
			PURL:     "pkg:jsr/%40std/encoding@1.0.5",
			Language: pkg.JavaScript,
			Type:     pkg.JsrPkg,
			Metadata: pkg.DenoLockEntry{
				Integrity:    "ecf363d4fc25bd85bd915ff6733a7e79b67e0e7806334af15f4645c569fefc04",
				Dependencies: []string{"jsr:@std/bytes@^1.0.0"},
			},
		},
		{
			Name:     "chalk",
			Version:  "5.3.0",
			PURL:     "pkg:npm/chalk@5.3.0",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Metadata: pkg.NpmPackageLockEntry{
				Integrity: "sha512-dLitG79d+GV1Nb/VYcCDFivJeK1hiukt9QjRNVOsUtTy1rR1YJsmpGGTZ3qJos+uw7WmWF4wUwBd9jxjocFC2w==",
			},
		},
		{
			Name:     "deno.land/std",
			Version:  "0.140.0",
			PURL:     "pkg:deno/deno.land%2Fstd@0.140.0",
			Language: pkg.JavaScript,
			Type:     pkg.JsrPkg,
			Metadata: pkg.DenoRemoteLockEntry{
				URL:       "https://deno.land/std@0.140.0/path/mod.ts",
				Integrity: "d3e68d0abb393fb0bf94a6d07c46ec31dc755b544b13144dee931d8d5f06a52d",
			},
		},
	}

	for i := range expectedPkgs {
		expectedPkgs[i].Locations.Add(file.NewLocation(fixture))
	}

	pkgtest.TestFileParser(t, fixture, parseDenoLock, expectedPkgs, expectedRelationships)
}

func Test_corruptDenoLock(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/corrupt/deno.lock").
		WithError().
		TestParser(t, parseDenoLock)
}
