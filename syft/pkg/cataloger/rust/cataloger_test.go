package rust

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
	"github.com/anchore/syft/syft/source"
)

func TestNewAuditBinaryCataloger(t *testing.T) {
	expectedPkgs := []pkg.Package{
		{
			Name:         "auditable",
			Version:      "0.1.0",
			PURL:         "pkg:cargo/auditable@0.1.0",
			FoundBy:      "cargo-auditable-binary-cataloger",
			Locations:    source.NewLocationSet(source.NewVirtualLocation("/hello-auditable", "/hello-auditable")),
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Metadata: pkg.CargoPackageMetadata{
				Name:    "auditable",
				Version: "0.1.0",
				Source:  "local",
			},
		},
		{
			Name:         "hello-auditable",
			Version:      "0.1.0",
			PURL:         "pkg:cargo/hello-auditable@0.1.0",
			FoundBy:      "cargo-auditable-binary-cataloger",
			Locations:    source.NewLocationSet(source.NewVirtualLocation("/hello-auditable", "/hello-auditable")),
			Language:     pkg.Rust,
			Type:         pkg.RustPkg,
			MetadataType: pkg.RustCargoPackageMetadataType,
			Metadata: pkg.CargoPackageMetadata{
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
