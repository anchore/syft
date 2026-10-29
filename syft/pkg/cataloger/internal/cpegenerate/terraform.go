package cpegenerate

import (
	"strings"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

// NVD records terraform providers with a fixed "terraform_provider" product and the provider type in target_sw, e.g.
// cpe:2.3:a:hashicorp:terraform_provider:*:*:*:*:*:vault:*:*
const terraformProviderProduct = "terraform_provider"

func candidateVendorsForTerraformProvider(p pkg.Package) fieldCandidateSet {
	vendors := newFieldCandidateSet()

	namespace, _ := parseTerraformProviderName(p.Name)
	if namespace != "" {
		vendors.addValue(namespace)
	}

	return vendors
}

func candidateProductsForTerraformProvider(p pkg.Package) fieldCandidateSet {
	products := newFieldCandidateSet()

	_, providerType := parseTerraformProviderName(p.Name)
	if providerType != "" {
		products.add(fieldCandidate{
			value:                       terraformProviderProduct,
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})
	}

	return products
}

func candidateTargetSwForTerraformProvider(p pkg.Package) []string {
	_, providerType := parseTerraformProviderName(p.Name)
	if providerType == "" {
		return []string{cpe.Any}
	}
	return []string{providerType}
}

// parseTerraformProviderName extracts the namespace and type from a terraform provider
// source address. The expected format is "registry.terraform.io/<namespace>/<type>".
func parseTerraformProviderName(name string) (namespace, providerType string) {
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}
