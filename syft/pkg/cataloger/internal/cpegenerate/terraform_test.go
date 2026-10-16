package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_candidateVendorsForTerraformProvider(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "hashicorp/aws provider",
			pkg: pkg.Package{
				Name: "registry.terraform.io/hashicorp/aws",
			},
			expected: []string{"hashicorp"},
		},
		{
			name: "grafana/grafana provider",
			pkg: pkg.Package{
				Name: "registry.terraform.io/grafana/grafana",
			},
			expected: []string{"grafana"},
		},
		{
			name: "hashicorp/google provider",
			pkg: pkg.Package{
				Name: "registry.terraform.io/hashicorp/google",
			},
			expected: []string{"hashicorp"},
		},
		{
			name: "malformed name with fewer than 3 segments",
			pkg: pkg.Package{
				Name: "hashicorp/aws",
			},
			expected: []string{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := candidateVendorsForTerraformProvider(test.pkg).uniqueValues()
			assert.ElementsMatch(t, test.expected, actual)
		})
	}
}

func Test_candidateProductsForTerraformProvider(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "hashicorp/aws provider",
			pkg: pkg.Package{
				Name: "registry.terraform.io/hashicorp/aws",
			},
			expected: []string{"terraform-provider-aws"},
		},
		{
			name: "grafana/grafana provider",
			pkg: pkg.Package{
				Name: "registry.terraform.io/grafana/grafana",
			},
			expected: []string{"terraform-provider-grafana"},
		},
		{
			name: "hashicorp/google provider",
			pkg: pkg.Package{
				Name: "registry.terraform.io/hashicorp/google",
			},
			expected: []string{"terraform-provider-google"},
		},
		{
			name: "malformed name with fewer than 3 segments",
			pkg: pkg.Package{
				Name: "hashicorp/aws",
			},
			expected: []string{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := candidateProductsForTerraformProvider(test.pkg).uniqueValues()
			assert.ElementsMatch(t, test.expected, actual)
		})
	}
}

func Test_parseTerraformProviderName(t *testing.T) {
	tests := []struct {
		name              string
		input             string
		expectedNamespace string
		expectedType      string
	}{
		{
			name:              "standard provider",
			input:             "registry.terraform.io/hashicorp/aws",
			expectedNamespace: "hashicorp",
			expectedType:      "aws",
		},
		{
			name:              "provider where namespace matches type",
			input:             "registry.terraform.io/grafana/grafana",
			expectedNamespace: "grafana",
			expectedType:      "grafana",
		},
		{
			name:              "too few segments",
			input:             "hashicorp/aws",
			expectedNamespace: "",
			expectedType:      "",
		},
		{
			name:              "single segment",
			input:             "aws",
			expectedNamespace: "",
			expectedType:      "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			namespace, providerType := parseTerraformProviderName(test.input)
			assert.Equal(t, test.expectedNamespace, namespace)
			assert.Equal(t, test.expectedType, providerType)
		})
	}
}
