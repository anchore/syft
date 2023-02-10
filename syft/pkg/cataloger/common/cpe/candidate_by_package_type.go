package cpe

import (
	"github.com/anchore/syft/syft/pkg"
)

// candidateComposite is a convenience when creating the defaultCandidateAdditions set
type candidateComposite struct {
	pkg.Type
	candidateKey
	candidateAddition
}

type candidateRemovalComposite struct {
	pkg.Type
	candidateKey
	candidateRemovals
}

// defaultCandidateAdditions is all of the known cases for product and vendor field values that should be used when
// select package information is discovered
var defaultCandidateAdditions = buildCandidateLookup(
	[]candidateComposite{
		// Java packages
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "springframework"},
			candidateAddition{AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"}, AdditionalVendors: []string{"pivotal_software", "springsource", "vmware"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "spring-core"},
			candidateAddition{AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"}, AdditionalVendors: []string{"pivotal_software", "springsource", "vmware"}},
		},
		{
			// example image: docker.io/nuxeo:latest
			pkg.JavaPkg,
			candidateKey{PkgName: "elasticsearch"}, // , Vendor: "elasticsearch"},
			candidateAddition{AdditionalVendors: []string{"elastic"}},
		},
		{
			// example image: docker.io/kaazing-gateway:latest
			pkg.JavaPkg,
			candidateKey{PkgName: "log4j"}, // , Vendor: "apache-software-foundation"},
			candidateAddition{AdditionalVendors: []string{"apache"}},
		},

		{
			// example image: cassandra:latest
			pkg.JavaPkg,
			candidateKey{PkgName: "apache-cassandra"}, // , Vendor: "apache"},
			candidateAddition{AdditionalProducts: []string{"cassandra"}},
		},
		{
			// example image: cloudbees/cloudbees-core-mm:2.319.3.4
			// this is a wrapped packaging of the handlebars.js node module
			pkg.JavaPkg,
			candidateKey{PkgName: "handlebars"},
			candidateAddition{AdditionalVendors: []string{"handlebarsjs"}},
		},
		// NPM packages
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "hapi"},
			candidateAddition{AdditionalProducts: []string{"hapi_server_framework"}},
		},
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "handlebars.js"},
			candidateAddition{AdditionalProducts: []string{"handlebars"}},
		},
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "is-my-json-valid"},
			candidateAddition{AdditionalProducts: []string{"is_my_json_valid"}},
		},
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "mustache"},
			candidateAddition{AdditionalProducts: []string{"mustache.js"}},
		},

		// Gem packages
		{
			pkg.GemPkg,
			candidateKey{PkgName: "Arabic-Prawn"},
			candidateAddition{AdditionalProducts: []string{"arabic_prawn"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "bio-basespace-sdk"},
			candidateAddition{AdditionalProducts: []string{"basespace_ruby_sdk"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "cremefraiche"},
			candidateAddition{AdditionalProducts: []string{"creme_fraiche"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "html-sanitizer"},
			candidateAddition{AdditionalProducts: []string{"html_sanitizer"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "sentry-raven"},
			candidateAddition{AdditionalProducts: []string{"raven-ruby"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "RedCloth"},
			candidateAddition{AdditionalProducts: []string{"redcloth_library"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "VladTheEnterprising"},
			candidateAddition{AdditionalProducts: []string{"vladtheenterprising"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "yajl-ruby"},
			candidateAddition{AdditionalProducts: []string{"yajl-ruby_gem"}},
		},
		// Python packages
		{
			pkg.PythonPkg,
			candidateKey{PkgName: "python-rrdtool"},
			candidateAddition{AdditionalProducts: []string{"rrdtool"}},
		},
		// Alpine packages
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "python3"},
			candidateAddition{AdditionalProducts: []string{"python"}, AdditionalVendors: []string{"python", "python_software_foundation"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "python"},
			candidateAddition{AdditionalVendors: []string{"python_software_foundation"}},
		},
	})

var defaultCandidateRemovals = buildCandidateRemovalLookup(
	[]candidateRemovalComposite{
		// Python packages
		{
			pkg.PythonPkg,
			candidateKey{PkgName: "redis"},
			candidateRemovals{VendorsToRemove: []string{"redis"}},
		},
	})

// buildCandidateLookup is a convenience function for creating the defaultCandidateAdditions set
func buildCandidateLookup(cc []candidateComposite) (ca map[pkg.Type]map[candidateKey]candidateAddition) {
	ca = make(map[pkg.Type]map[candidateKey]candidateAddition)
	for _, c := range cc {
		if _, ok := ca[c.Type]; !ok {
			ca[c.Type] = make(map[candidateKey]candidateAddition)
		}
		ca[c.Type][c.candidateKey] = c.candidateAddition
	}

	return ca
}

// buildCandidateRemovalLookup is a convenience function for creating the defaultCandidateRemovals set
func buildCandidateRemovalLookup(cc []candidateRemovalComposite) (ca map[pkg.Type]map[candidateKey]candidateRemovals) {
	ca = make(map[pkg.Type]map[candidateKey]candidateRemovals)
	for _, c := range cc {
		if _, ok := ca[c.Type]; !ok {
			ca[c.Type] = make(map[candidateKey]candidateRemovals)
		}
		ca[c.Type][c.candidateKey] = c.candidateRemovals
	}
	return ca
}

// candidateKey represents the set of inputs that should be matched on in order to signal more candidate additions to be used.
type candidateKey struct {
	Vendor  string
	PkgName string
}

// candidateRemovals are the specific removals that should be considered during CPE generation (given a specific candidateKey)
type candidateRemovals struct {
	ProductsToRemove []string
	VendorsToRemove  []string
}

// candidateAddition are the specific additions that should be considered during CPE generation (given a specific candidateKey)
type candidateAddition struct {
	AdditionalProducts []string
	AdditionalVendors  []string
}

// findAdditionalVendors searches all possible vendor additions that could be added during the CPE generation process (given package info + a vendor candidate)
func findAdditionalVendors(allAdditions map[pkg.Type]map[candidateKey]candidateAddition, ty pkg.Type, pkgName, vendor string) (vendors []string) {
	additions, ok := allAdditions[ty]
	if !ok {
		return nil
	}

	if addition, ok := additions[candidateKey{
		Vendor:  vendor,
		PkgName: pkgName,
	}]; ok {
		vendors = append(vendors, addition.AdditionalVendors...)
	}

	if addition, ok := additions[candidateKey{
		PkgName: pkgName,
	}]; ok {
		vendors = append(vendors, addition.AdditionalVendors...)
	}

	if addition, ok := additions[candidateKey{
		Vendor: vendor,
	}]; ok {
		vendors = append(vendors, addition.AdditionalVendors...)
	}

	return vendors
}

// findAdditionalProducts searches all possible product additions that could be added during the CPE generation process (given package info)
func findAdditionalProducts(allAdditions map[pkg.Type]map[candidateKey]candidateAddition, ty pkg.Type, pkgName string) (products []string) {
	additions, ok := allAdditions[ty]
	if !ok {
		return nil
	}

	if addition, ok := additions[candidateKey{
		PkgName: pkgName,
	}]; ok {
		products = append(products, addition.AdditionalProducts...)
	}

	return products
}

// findVendorsToRemove searches all possible vendor removals that could be removed during the CPE generation process (given package info + a vendor candidate)
func findVendorsToRemove(allRemovals map[pkg.Type]map[candidateKey]candidateRemovals, ty pkg.Type, pkgName string) (vendors []string) {
	removals, ok := allRemovals[ty]
	if !ok {
		return nil
	}

	if removal, ok := removals[candidateKey{
		PkgName: pkgName,
	}]; ok {
		vendors = append(vendors, removal.VendorsToRemove...)
	}

	return vendors
}

// findProductsToRemove searches all possible product removals that could be removed during the CPE generation process (given package info)
func findProductsToRemove(allRemovals map[pkg.Type]map[candidateKey]candidateRemovals, ty pkg.Type, pkgName string) (products []string) {
	removals, ok := allRemovals[ty]
	if !ok {
		return nil
	}

	if removal, ok := removals[candidateKey{
		PkgName: pkgName,
	}]; ok {
		products = append(products, removal.ProductsToRemove...)
	}

	return products
}
