package hadron

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseComponents(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/components.json").
		IgnorePackageFields("Locations").
		Expects([]pkg.Package{
			{Name: "busybox", Version: "1.37.0", Type: pkg.HadronPkg, PURL: "pkg:hadron/busybox@1.37.0"},
			{Name: "curl", Version: "8.21.0", Type: pkg.HadronPkg, PURL: "pkg:hadron/curl@8.21.0"},
			{Name: "musl", Version: "1.2.6", Type: pkg.HadronPkg, PURL: "pkg:hadron/musl@1.2.6"},
			{Name: "openssl", Version: "3.6.3", Type: pkg.HadronPkg, PURL: "pkg:hadron/openssl@3.6.3"},
			{Name: "zlib", Version: "1.3.2", Type: pkg.HadronPkg, PURL: "pkg:hadron/zlib@1.3.2"},
		}, nil).
		TestParser(t, parseComponents)
}
