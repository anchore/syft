package cpe

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_additionalProducts(t *testing.T) {
	tests := []struct {
		name         string
		allAdditions map[pkg.Type]map[candidateAdditionKey]candidateAddition
		ty           pkg.Type
		pkgName      string
		expected     []string
	}{
		{
			name: "product name addition",
			allAdditions: map[pkg.Type]map[candidateAdditionKey]candidateAddition{
				pkg.JavaPkg: {
					candidateAdditionKey{
						PkgName: "spring-core",
					}: {
						AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "spring-core",
			expected: []string{"spring_framework", "springsource_spring_framework"},
		},
		{
			name: "no addition found",
			allAdditions: map[pkg.Type]map[candidateAdditionKey]candidateAddition{
				pkg.JavaPkg: {
					candidateAdditionKey{
						PkgName: "spring-core",
					}: {
						AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "nothing",
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, additionalProducts(test.allAdditions, test.ty, test.pkgName))
		})
	}
}

func Test_additionalVendors(t *testing.T) {
	tests := []struct {
		name         string
		allAdditions map[pkg.Type]map[candidateAdditionKey]candidateAddition
		ty           pkg.Type
		pkgName      string
		vendor       string
		expected     []string
	}{
		{
			name: "vendor addition by input vendor",
			allAdditions: map[pkg.Type]map[candidateAdditionKey]candidateAddition{
				pkg.JavaPkg: {
					candidateAdditionKey{
						Vendor: "my-vendor",
					}: {
						AdditionalVendors: []string{"awesome-vendor-addition"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "spring-core",
			vendor:   "my-vendor",
			expected: []string{"awesome-vendor-addition"},
		},
		{
			name: "vendor addition by input package name",
			allAdditions: map[pkg.Type]map[candidateAdditionKey]candidateAddition{
				pkg.JavaPkg: {
					candidateAdditionKey{
						PkgName: "my-package-name",
					}: {
						AdditionalVendors: []string{"awesome-vendor-addition"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "my-package-name",
			vendor:   "my-vendor",
			expected: []string{"awesome-vendor-addition"},
		},
		{
			name: "vendor addition by input package name + vendor",
			allAdditions: map[pkg.Type]map[candidateAdditionKey]candidateAddition{
				pkg.JavaPkg: {
					candidateAdditionKey{
						PkgName: "my-package-name",
						Vendor:  "my-vendor",
					}: {
						AdditionalVendors: []string{"awesome-vendor-addition"},
					},
					// note: the below keys should not be matched
					candidateAdditionKey{
						PkgName: "my-package-name",
					}: {
						AdditionalVendors: []string{"bad-addition"},
					},
					// note: the below keys should not be matched
					candidateAdditionKey{
						Vendor: "my-vendor",
					}: {
						AdditionalVendors: []string{"bad-addition"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "my-package-name",
			vendor:   "my-vendor",
			expected: []string{"awesome-vendor-addition"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, additionalVendors(test.allAdditions, test.ty, test.pkgName, test.vendor))
		})
	}
}
