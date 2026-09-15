package cpegenerate

import (
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

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
		products.addValue("terraform-provider-" + providerType)
	}

	return products
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
