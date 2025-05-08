package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_additionalProducts(t *testing.T) {
	tests := []struct {
		name         string
		allAdditions map[pkg.Type]map[candidateKey]candidateAddition
		ty           pkg.Type
		pkgName      string
		expected     []string
	}{
		{
			name: "product name addition",
			allAdditions: map[pkg.Type]map[candidateKey]candidateAddition{
				pkg.JavaPkg: {
					candidateKey{
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
			allAdditions: map[pkg.Type]map[candidateKey]candidateAddition{
				pkg.JavaPkg: {
					candidateKey{
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
			assert.Equal(t, test.expected, findAdditionalProducts(test.allAdditions, test.ty, test.pkgName))
		})
	}
}

func Test_additionalVendors(t *testing.T) {
	tests := []struct {
		name         string
		allAdditions map[pkg.Type]map[candidateKey]candidateAddition
		ty           pkg.Type
		pkgName      string
		vendor       string
		expected     []string
	}{
		{
			name: "vendor addition by input vendor",
			allAdditions: map[pkg.Type]map[candidateKey]candidateAddition{
				pkg.JavaPkg: {
					candidateKey{
						Vendor: "my-vendor",
					}: {
						AdditionalVendors: []string{"awesome-vendor-addition"},
					},
					// note: the below keys should not be matched
					candidateKey{
						PkgName: "my-package-name",
						Vendor:  "my-vendor",
					}: {
						AdditionalVendors: []string{"bad-addition"},
					},
					candidateKey{
						PkgName: "my-package-name",
					}: {
						AdditionalVendors: []string{"bad-addition"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "NOT-MY-PACKAGE",
			vendor:   "my-vendor",
			expected: []string{"awesome-vendor-addition"},
		},
		{
			name: "vendor addition by input package name",
			allAdditions: map[pkg.Type]map[candidateKey]candidateAddition{
				pkg.JavaPkg: {
					candidateKey{
						PkgName: "my-package-name",
					}: {
						AdditionalVendors: []string{"awesome-vendor-addition"},
					},
					// note: the below keys should not be matched
					candidateKey{
						PkgName: "my-package-name",
						Vendor:  "my-vendor",
					}: {
						AdditionalVendors: []string{"bad-addition"},
					},
					candidateKey{
						Vendor: "my-vendor",
					}: {
						AdditionalVendors: []string{"bad-addition"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "my-package-name",
			vendor:   "NOT-MY-VENDOR",
			expected: []string{"awesome-vendor-addition"},
		},
		{
			name: "vendor addition by input package name + vendor",
			allAdditions: map[pkg.Type]map[candidateKey]candidateAddition{
				pkg.JavaPkg: {
					candidateKey{
						PkgName: "my-package-name",
						Vendor:  "my-vendor",
					}: {
						AdditionalVendors: []string{"awesome-vendor-addition"},
					},
					// note: the below keys should not be matched
					candidateKey{
						PkgName: "my-package-name",
					}: {
						AdditionalVendors: []string{"one-good-addition"},
					},
					candidateKey{
						Vendor: "my-vendor",
					}: {
						AdditionalVendors: []string{"another-good-addition"},
					},
				},
			},
			ty:       pkg.JavaPkg,
			pkgName:  "my-package-name",
			vendor:   "my-vendor",
			expected: []string{"awesome-vendor-addition", "one-good-addition", "another-good-addition"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, findAdditionalVendors(test.allAdditions, test.ty, test.pkgName, test.vendor))
		})
	}
}

func Test_findVendorsToRemove(t *testing.T) {
	//GIVEN
	tests := []struct {
		name     string
		ty       pkg.Type
		pkgName  string
		expected []string
	}{
		{
			name:     "vendor removal match by input package name",
			ty:       pkg.JavaPkg,
			pkgName:  "my-package-name",
			expected: []string{"awesome-vendor-addition"},
		},
		{
			name:    "vendor removal miss by input package name",
			ty:      pkg.JavaPkg,
			pkgName: "my-package-name-1",
		},
	}

	allRemovals := map[pkg.Type]map[candidateKey]candidateRemovals{
		pkg.JavaPkg: {
			candidateKey{
				PkgName: "my-package-name",
			}: {
				VendorsToRemove: []string{"awesome-vendor-addition"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			//WHEN + THEN
			assert.Equal(t, test.expected, findVendorsToRemove(allRemovals, test.ty, test.pkgName))
		})
	}
}

func Test_findProductsToRemove(t *testing.T) {
	//GIVEN
	tests := []struct {
		name     string
		ty       pkg.Type
		pkgName  string
		expected []string
	}{
		{
			name:     "vendor removal match by input package name",
			ty:       pkg.JavaPkg,
			pkgName:  "my-package-name",
			expected: []string{"awesome-vendor-addition"},
		},
		{
			name:    "vendor removal miss by input package name",
			ty:      pkg.JavaPkg,
			pkgName: "my-package-name-1",
		},
	}

	allRemovals := map[pkg.Type]map[candidateKey]candidateRemovals{
		pkg.JavaPkg: {
			candidateKey{
				PkgName: "my-package-name",
			}: {
				ProductsToRemove: []string{"awesome-vendor-addition"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			//WHEN + THEN
			assert.Equal(t, test.expected, findProductsToRemove(allRemovals, test.ty, test.pkgName))
		})
	}
}
