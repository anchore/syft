package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseDenoLock(t *testing.T) {
	fixture := "test-fixtures/deno/deno.lock"

	expectedPkgs := []pkg.Package{
		{
			Name:     "@std/bytes",
			Version:  "1.0.2",
			PURL:     "pkg:npm/%40std/bytes@1.0.2?repository_url=https%3A%2F%2Fjsr.io",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Metadata: pkg.DenoLockEntry{
				Integrity: "fbdee322bbd8c599a6af186a1603b3355e59a5fb1baa139f8f4c3c9a1b3e3d57",
			},
		},
		{
			Name:     "@std/encoding",
			Version:  "1.0.5",
			PURL:     "pkg:npm/%40std/encoding@1.0.5?repository_url=https%3A%2F%2Fjsr.io",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
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
			PURL:     "pkg:npm/deno.land%2Fstd@0.140.0?repository_url=https%3A%2F%2Fdeno.land",
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Metadata: pkg.DenoRemoteLockEntry{
				URL:       "https://deno.land/std@0.140.0/path/mod.ts",
				Integrity: "d3e68d0abb393fb0bf94a6d07c46ec31dc755b544b13144dee931d8d5f06a52d",
			},
		},
	}

	for i := range expectedPkgs {
		expectedPkgs[i].Locations.Add(file.NewLocation(fixture))
	}

	// @std/encoding depends  => @std/bytes
	expectedRelationships := []artifact.Relationship{
		{
			From: expectedPkgs[0], // @std/bytes main
			To:   expectedPkgs[1], // @std/encoding dep
			Type: artifact.DependencyOfRelationship,
		},
	}

	adapter := newGenericDenoLockAdapter(DefaultCatalogerConfig())
	pkgtest.TestFileParser(t, fixture, adapter.parseDenoLock, expectedPkgs, expectedRelationships)
}

func Test_corruptDenoLock(t *testing.T) {
	adapter := newGenericDenoLockAdapter(DefaultCatalogerConfig())
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/deno/corrupt/deno.lock").
		WithError().
		TestParser(t, adapter.parseDenoLock)
}
