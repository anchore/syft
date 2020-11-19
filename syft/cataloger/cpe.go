package cataloger

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

// this is functionally equivalent to "*" and consistent with no input given (thus easier to test)
const any = ""

// generatePackageCPEs Create a list of CPEs, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func generatePackageCPEs(p pkg.Package) []pkg.CPE {
	targetSws := candidateTargetSoftwareAttrs(p)
	vendors := candidateVendors(p)
	products := candidateProducts(p)

	keys := internal.NewStringSet()
	cpes := make([]pkg.CPE, 0)
	for _, product := range products {
		for _, vendor := range append([]string{any}, vendors...) {
			for _, targetSw := range append([]string{any}, targetSws...) {
				// prevent duplicate entries...
				key := fmt.Sprintf("%s|%s|%s|%s", product, vendor, p.Version, targetSw)
				if keys.Contains(key) {
					continue
				}
				keys.Add(key)

				// add a new entry...
				candidateCpe := wfn.NewAttributesWithAny()
				candidateCpe.Product = product
				candidateCpe.Vendor = vendor
				candidateCpe.Version = p.Version
				candidateCpe.TargetSW = targetSw

				cpes = append(cpes, *candidateCpe)
			}
		}
	}

	return cpes
}

func candidateTargetSoftwareAttrs(p pkg.Package) []string {
	// TODO: expand with package metadata (from type assert)

	// TODO: would be great to allow these to be overridden by user data/config
	var targetSw []string
	switch p.Language {
	case pkg.Java:
		targetSw = append(targetSw, "java", "maven")
	case pkg.JavaScript:
		targetSw = append(targetSw, "node.js", "nodejs")
	case pkg.Ruby:
		targetSw = append(targetSw, "ruby", "rails")
	case pkg.Python:
		targetSw = append(targetSw, "python")
	}

	if p.Type == pkg.JenkinsPluginPkg {
		targetSw = append(targetSw, "jenkins", "cloudbees_jenkins")
	}

	return targetSw
}

func candidateVendors(p pkg.Package) []string {
	// TODO: expand with package metadata (from type assert)
	vendors := []string{p.Name}
	if p.Language == pkg.Python {
		vendors = append(vendors, fmt.Sprintf("python-%s", p.Name))
	}
	return vendors
}

func candidateProducts(p pkg.Package) []string {
	return []string{p.Name}
}
