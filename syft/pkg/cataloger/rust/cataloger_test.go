package rust

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestNewAuditBinaryCataloger(t *testing.T) {

	expectedPkgs := []pkg.Package{
		{
			Name:      "auditable",
			Version:   "0.1.0",
			PURL:      "pkg:cargo/auditable@0.1.0",
			FoundBy:   "cargo-auditable-binary-cataloger",
			Locations: file.NewLocationSet(file.NewVirtualLocation("/hello-auditable", "/hello-auditable")),
			Language:  pkg.Rust,
			Type:      pkg.RustPkg,
			Metadata: pkg.RustBinaryAuditEntry{
				Name:    "auditable",
				Version: "0.1.0",
				Source:  "local",
			},
		},
		{
			Name:      "hello-auditable",
			Version:   "0.1.0",
			PURL:      "pkg:cargo/hello-auditable@0.1.0",
			FoundBy:   "cargo-auditable-binary-cataloger",
			Locations: file.NewLocationSet(file.NewVirtualLocation("/hello-auditable", "/hello-auditable")),
			Language:  pkg.Rust,
			Type:      pkg.RustPkg,
			Metadata: pkg.RustBinaryAuditEntry{
				Name:    "hello-auditable",
				Version: "0.1.0",
				Source:  "local",
			},
		},
	}

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-audit").
		IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
		Expects(expectedPkgs, nil).
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
