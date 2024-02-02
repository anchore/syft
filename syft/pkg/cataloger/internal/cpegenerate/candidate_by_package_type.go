package cpegenerate

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
			// example image: docker.io/jenkins/jenkins:latest
			pkg.JavaPkg,
			candidateKey{PkgName: "spring-security-core"},
			candidateAddition{AdditionalProducts: []string{"spring_security"}, AdditionalVendors: []string{"vmware"}},
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
		{
			pkg.GemPkg,
			candidateKey{PkgName: "cgi"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "date"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "openssl"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "rake"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "rdoc"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "rexml"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "trunk"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "webrick"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		// Python packages
		{
			pkg.PythonPkg,
			candidateKey{PkgName: "python-rrdtool"},
			candidateAddition{AdditionalProducts: []string{"rrdtool"}},
		},
		{
			pkg.PythonPkg,
			candidateKey{PkgName: "cryptography"},
			candidateAddition{AdditionalProducts: []string{"python-cryptography"}, AdditionalVendors: []string{"python-cryptography_project"}},
		},
		{
			pkg.PythonPkg,
			candidateKey{PkgName: "pip"},
			candidateAddition{AdditionalVendors: []string{"pypa"}},
		},
		{
			pkg.PythonPkg,
			candidateKey{PkgName: "Django"},
			candidateAddition{AdditionalVendors: []string{"djangoproject"}},
		},
		// Alpine packages
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "curl"},
			candidateAddition{AdditionalVendors: []string{"haxx"}},
		},
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
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "nodejs"},
			candidateAddition{AdditionalProducts: []string{"node.js"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "nodejs-current"},
			candidateAddition{AdditionalProducts: []string{"node.js"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "go"},
			candidateAddition{AdditionalVendors: []string{"golang"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "ruby"},
			candidateAddition{AdditionalVendors: []string{"ruby-lang"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "bazel"},
			candidateAddition{AdditionalVendors: []string{"google"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "clang"},
			candidateAddition{AdditionalVendors: []string{"llvm"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "openjdk"},
			candidateAddition{AdditionalVendors: []string{"oracle"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "glibc"},
			candidateAddition{AdditionalVendors: []string{"gnu"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "glib"},
			candidateAddition{AdditionalVendors: []string{"gnome"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "bash"},
			candidateAddition{AdditionalVendors: []string{"gnu"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "alsa-lib"},
			candidateAddition{AdditionalVendors: []string{"alsa-project"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "alsa"},
			candidateAddition{AdditionalVendors: []string{"alsa-project"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "make"},
			candidateAddition{AdditionalVendors: []string{"gnu"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "git"},
			candidateAddition{AdditionalVendors: []string{"git-scm"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "bind"},
			candidateAddition{AdditionalVendors: []string{"isc"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "libxpm"},
			candidateAddition{AdditionalVendors: []string{"libxpm_project"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "musl"},
			candidateAddition{AdditionalVendors: []string{"musl-libc"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "firefox"},
			candidateAddition{AdditionalVendors: []string{"mozilla"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "firefox-esr"},
			candidateAddition{AdditionalVendors: []string{"mozilla"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "thunderbird"},
			candidateAddition{AdditionalVendors: []string{"mozilla"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "chromium"},
			candidateAddition{AdditionalVendors: []string{"google"}, AdditionalProducts: []string{"chrome"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "apache"},
			candidateAddition{AdditionalProducts: []string{"http_server"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "tiff"},
			candidateAddition{AdditionalProducts: []string{"libtiff"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "ghostscript"},
			candidateAddition{AdditionalVendors: []string{"artifex"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "openjpeg"},
			candidateAddition{AdditionalVendors: []string{"uclouvain"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "xorg-server"},
			candidateAddition{AdditionalVendors: []string{"x.org"}, AdditionalProducts: []string{"x_server"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "podofo"},
			candidateAddition{AdditionalVendors: []string{"podofo_project"}},
		},
		{
			pkg.ApkPkg,
			candidateKey{PkgName: "wpa_supplicant"},
			candidateAddition{AdditionalVendors: []string{"w1.fi"}},
		},
		//
		// Binary packages
		{
			pkg.BinaryPkg,
			candidateKey{PkgName: "node"},
			candidateAddition{AdditionalProducts: []string{"nodejs", "node.js"}},
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
		{
			pkg.PythonPkg,
			candidateKey{PkgName: "kubernetes"},
			candidateRemovals{ProductsToRemove: []string{"kubernetes"}},
		},
		// NPM packages
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "redis"},
			candidateRemovals{VendorsToRemove: []string{"redis"}},
		},
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "php"},
			candidateRemovals{VendorsToRemove: []string{"php"}},
		},
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "delegate"},
			candidateRemovals{VendorsToRemove: []string{"delegate"}},
		},
		{
			pkg.NpmPkg,
			candidateKey{PkgName: "docker"},
			candidateRemovals{VendorsToRemove: []string{"docker"}},
		},
		// Java packages
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-builder-support"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-model"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-repository-metadata"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-settings"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-settings-builder"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-api"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-connector-basic"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-impl"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-named-locks"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-spi"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-transport-file"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-transport-http"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-transport-wagon"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-resolver-util"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "maven-shared-utils"},
			candidateRemovals{ProductsToRemove: []string{"maven"}},
		},
		{
			pkg.JavaPkg,
			candidateKey{PkgName: "gradle-enterprise"},
			candidateRemovals{
				ProductsToRemove: []string{"gradle-enterprise"},
				VendorsToRemove:  []string{"gradle"},
			},
		},
		// Ruby packages
		{
			pkg.GemPkg,
			candidateKey{PkgName: "redis"},
			candidateRemovals{ProductsToRemove: []string{"redis"}},
		},
		{
			pkg.GemPkg,
			candidateKey{PkgName: "grpc"},
			candidateRemovals{ProductsToRemove: []string{"grpc"}},
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
