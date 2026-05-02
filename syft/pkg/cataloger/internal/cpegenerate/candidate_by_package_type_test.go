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

// Regression test for https://github.com/anchore/syft/issues/4653:
// NVD records React under the facebook vendor, so the default npm-derived
// CPE (cpe:2.3:a:react:react:*) misses every React CVE. The candidate
// table must add "facebook" to the list of candidate vendors for react
// (and react-dom, which is tied to the same CVE stream).
func Test_npmCandidateAdditions_react(t *testing.T) {
	tests := []struct {
		pkgName         string
		expectedVendors []string
	}{
		{pkgName: "react", expectedVendors: []string{"facebook"}},
		{pkgName: "react-dom", expectedVendors: []string{"facebook"}},
	}
	for _, test := range tests {
		t.Run(test.pkgName, func(t *testing.T) {
			got := findAdditionalVendors(defaultCandidateAdditions, pkg.NpmPkg, test.pkgName, "")
			assert.ElementsMatch(t, test.expectedVendors, got,
				"npm package %q should map to vendors %v", test.pkgName, test.expectedVendors)
		})
	}
}

// Regression test for https://github.com/anchore/syft/issues/4712:
// libpcap is maintained by the tcpdump project and NVD records the CVEs
// under vendor "tcpdump". Without this hint the APK-derived CPE
// (cpe:2.3:a:libpcap:libpcap:*) fails to match any NVD entry and grype
// reports zero vulnerabilities for a known-vulnerable libpcap version.
func Test_apkCandidateAdditions_libpcap(t *testing.T) {
	got := findAdditionalVendors(defaultCandidateAdditions, pkg.ApkPkg, "libpcap", "")
	assert.Contains(t, got, "tcpdump",
		"apk package libpcap should map to the tcpdump vendor for NVD matching")
}

// Regression test for https://github.com/anchore/syft/issues/4771:
// NVD records expat CVEs under product "libexpat" (vendor "libexpat"),
// so without a hint the conan-derived cpe:2.3:a:expat:expat:* fails
// to match every recent expat CVE like CVE-2024-45492.
func Test_conanCandidateAdditions_expat(t *testing.T) {
	vendors := findAdditionalVendors(defaultCandidateAdditions, pkg.ConanPkg, "expat", "")
	assert.Contains(t, vendors, "libexpat",
		"conan package expat should map to the libexpat vendor for NVD matching")
	products := findAdditionalProducts(defaultCandidateAdditions, pkg.ConanPkg, "expat")
	assert.Contains(t, products, "libexpat",
		"conan package expat should also emit libexpat as a candidate product")
}
