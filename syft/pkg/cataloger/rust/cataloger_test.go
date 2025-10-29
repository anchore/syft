package rust

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestNewAuditBinaryCataloger(t *testing.T) {
	locations := file.NewLocationSet(file.NewVirtualLocation("/usr/local/bin/hello_world", "/usr/local/bin/hello_world"))

	argh := pkg.Package{
		Name:      "argh",
		Version:   "0.1.12",
		PURL:      "pkg:cargo/argh@0.1.12",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "argh",
			Version: "0.1.12",
			Source:  "crates.io",
		},
	}

	arghDerive := pkg.Package{
		Name:      "argh_derive",
		Version:   "0.1.12",
		PURL:      "pkg:cargo/argh_derive@0.1.12",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "argh_derive",
			Version: "0.1.12",
			Source:  "crates.io",
		},
	}

	arghShared := pkg.Package{
		Name:      "argh_shared",
		Version:   "0.1.12",
		PURL:      "pkg:cargo/argh_shared@0.1.12",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "argh_shared",
			Version: "0.1.12",
			Source:  "crates.io",
		},
	}

	helloWorld := pkg.Package{
		Name:      "hello_world",
		Version:   "0.1.0",
		PURL:      "pkg:cargo/hello_world@0.1.0",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "hello_world",
			Version: "0.1.0",
			Source:  "local",
		},
	}

	procMacro2 := pkg.Package{
		Name:      "proc-macro2",
		Version:   "1.0.92",
		PURL:      "pkg:cargo/proc-macro2@1.0.92",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "proc-macro2",
			Version: "1.0.92",
			Source:  "crates.io",
		},
	}

	quote := pkg.Package{
		Name:      "quote",
		Version:   "1.0.37",
		PURL:      "pkg:cargo/quote@1.0.37",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "quote",
			Version: "1.0.37",
			Source:  "crates.io",
		},
	}

	serde := pkg.Package{
		Name:      "serde",
		Version:   "1.0.215",
		PURL:      "pkg:cargo/serde@1.0.215",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "serde",
			Version: "1.0.215",
			Source:  "crates.io",
		},
	}

	serdeDerive := pkg.Package{
		Name:      "serde_derive",
		Version:   "1.0.215",
		PURL:      "pkg:cargo/serde_derive@1.0.215",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "serde_derive",
			Version: "1.0.215",
			Source:  "crates.io",
		},
	}

	syn := pkg.Package{
		Name:      "syn",
		Version:   "2.0.90",
		PURL:      "pkg:cargo/syn@2.0.90",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "syn",
			Version: "2.0.90",
			Source:  "crates.io",
		},
	}

	unicodeIdent := pkg.Package{
		Name:      "unicode-ident",
		Version:   "1.0.14",
		PURL:      "pkg:cargo/unicode-ident@1.0.14",
		Locations: locations,
		Language:  pkg.Rust,
		Type:      pkg.RustPkg,
		Metadata: pkg.RustBinaryAuditEntry{
			Name:    "unicode-ident",
			Version: "1.0.14",
			Source:  "crates.io",
		},
	}

	expectedPkgs := []pkg.Package{
		argh,
		arghDerive,
		arghShared,
		helloWorld,
		procMacro2,
		quote,
		serde,
		serdeDerive,
		syn,
		unicodeIdent,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: argh,
			To:   helloWorld,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: arghDerive,
			To:   argh,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: arghShared,
			To:   argh,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: arghShared,
			To:   arghDerive,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: procMacro2,
			To:   arghDerive,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: procMacro2,
			To:   quote,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: procMacro2,
			To:   serdeDerive,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: procMacro2,
			To:   syn,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: quote,
			To:   arghDerive,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: quote,
			To:   serdeDerive,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: quote,
			To:   syn,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serde,
			To:   arghShared,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serdeDerive,
			To:   serde,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: syn,
			To:   arghDerive,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: syn,
			To:   serdeDerive,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: unicodeIdent,
			To:   procMacro2,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: unicodeIdent,
			To:   syn,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-audit").
		IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
		Expects(expectedPkgs, expectedRelationships).
		TestCataloger(t, NewAuditBinaryCataloger())
}

func Test_CargoLockCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain Cargo.lock files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"src/Cargo.lock",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewCargoLockCataloger())
		})
	}
}

func Test_AuditBinaryCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain audit binary files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"partial-binary",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewAuditBinaryCataloger())
		})
	}
}

func Test_corruptAuditBinary(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/partial-binary").
		WithError().
		TestParser(t, parseAuditBinary)
}
