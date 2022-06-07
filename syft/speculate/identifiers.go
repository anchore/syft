package speculate

import (
	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/speculate/cpes"
)

func Identifiers(p *pkg.Package, release *linux.Release) {
	// generate CPEs (note: this is excluded from package ID, so is safe to mutate)
	p.CPEs = cpes.Generate(*p)

	// generate PURL (note: this is excluded from package ID, so is safe to mutate)
	p.PURL = pkg.URL(*p, release)
}
