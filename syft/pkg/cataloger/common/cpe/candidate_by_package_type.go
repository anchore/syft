package cpe

import (
	"github.com/anchore/syft/syft/pkg"
)

var productCandidatesByPkgType = candidatesByPackageType{
	pkg.JavaPkg: {
		"springframework": []string{"spring_framework", "springsource_spring_framework"},
		"spring-core":     []string{"spring_framework", "springsource_spring_framework"},
	},
	pkg.NpmPkg: {
		"hapi":             []string{"hapi_server_framework"},
		"handlebars.js":    []string{"handlebars"},
		"is-my-json-valid": []string{"is_my_json_valid"},
		"mustache":         []string{"mustache.js"},
	},
	pkg.GemPkg: {
		"Arabic-Prawn":        []string{"arabic_prawn"},
		"bio-basespace-sdk":   []string{"basespace_ruby_sdk"},
		"cremefraiche":        []string{"creme_fraiche"},
		"html-sanitizer":      []string{"html_sanitizer"},
		"sentry-raven":        []string{"raven-ruby"},
		"RedCloth":            []string{"redcloth_library"},
		"VladTheEnterprising": []string{"vladtheenterprising"},
		"yajl-ruby":           []string{"yajl-ruby_gem"},
	},
	pkg.PythonPkg: {
		"python-rrdtool": []string{"rrdtool"},
	},
}

// this is a static mapping of known package names (keys) to official cpe names for each package
type candidatesByPackageType map[pkg.Type]map[string][]string

/////////////////////////////

var candidateAdditions = map[pkg.Type]map[candidateAdditionKey]candidateAddition{
	pkg.JavaPkg: {
		candidateAdditionKey{
			PkgName: "springframework",
		}: {
			AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"},
		},
		candidateAdditionKey{
			PkgName: "spring-core",
		}: {
			AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"},
		},
	},
	pkg.NpmPkg: {
		//"hapi":             []string{"hapi_server_framework"},
		candidateAdditionKey{
			PkgName: "hapi",
		}: {
			AdditionalProducts: []string{"hapi_server_framework"},
		},
		//"handlebars.js":    []string{"handlebars"},
		candidateAdditionKey{
			PkgName: "handlebars.js",
		}: {
			AdditionalProducts: []string{"handlebars"},
		},
		//"is-my-json-valid": []string{"is_my_json_valid"},
		candidateAdditionKey{
			PkgName: "is-my-json-valid",
		}: {
			AdditionalProducts: []string{"is_my_json_valid"},
		},
		//"mustache":         []string{"mustache.js"},
		candidateAdditionKey{
			PkgName: "mustache",
		}: {
			AdditionalProducts: []string{"mustache.js"},
		},
	},
	pkg.GemPkg: {
		//"Arabic-Prawn":        []string{"arabic_prawn"},
		candidateAdditionKey{
			PkgName: "Arabic-Prawn",
		}: {
			AdditionalProducts: []string{"arabic_prawn"},
		},
		//"bio-basespace-sdk":   []string{"basespace_ruby_sdk"},
		candidateAdditionKey{
			PkgName: "bio-basespace-sdk",
		}: {
			AdditionalProducts: []string{"basespace_ruby_sdk"},
		},
		//"cremefraiche":        []string{"creme_fraiche"},
		candidateAdditionKey{
			PkgName: "cremefraiche",
		}: {
			AdditionalProducts: []string{"creme_fraiche"},
		},
		//"html-sanitizer":      []string{"html_sanitizer"},
		candidateAdditionKey{
			PkgName: "html-sanitizer",
		}: {
			AdditionalProducts: []string{"html_sanitizer"},
		},
		//"sentry-raven":        []string{"raven-ruby"},
		candidateAdditionKey{
			PkgName: "sentry-raven",
		}: {
			AdditionalProducts: []string{"raven-ruby"},
		},
		//"RedCloth":            []string{"redcloth_library"},
		candidateAdditionKey{
			PkgName: "RedCloth",
		}: {
			AdditionalProducts: []string{"redcloth_library"},
		},
		//"VladTheEnterprising": []string{"vladtheenterprising"},
		candidateAdditionKey{
			PkgName: "VladTheEnterprising",
		}: {
			AdditionalProducts: []string{"vladtheenterprising"},
		},
		//"yajl-ruby":           []string{"yajl-ruby_gem"},
		candidateAdditionKey{
			PkgName: "yajl-ruby",
		}: {
			AdditionalProducts: []string{"yajl-ruby_gem"},
		},
	},
	pkg.PythonPkg: {
		//"python-rrdtool": []string{"rrdtool"},
		candidateAdditionKey{
			PkgName: "python-rrdtool",
		}: {
			AdditionalProducts: []string{"rrdtool"},
		},
	},
}

type candidateAdditionKey struct {
	// The following fields are considered jointly
	Vendor  string // empty value means no constraint
	PkgName string // empty value means no constraint
}

type candidateAddition struct {
	// Add additional values to consider as field candidates
	AdditionalProducts []string
	AdditionalVendors  []string
}

// type + package name -> product name addition(s)
// type + vendor name -> vendor name addition(s)
// type + package name + vendor name -> vendor name addition(s)

// AdditionalVendors(type, product, vendor)
func additionalVendors(allAdditions map[pkg.Type]map[candidateAdditionKey]candidateAddition, ty pkg.Type, pkgName, vendor string) (vendors []string) {
	// TODO: rename
	typedAddition, ok := allAdditions[ty]
	if !ok {
		return nil
	}

	if additions, ok := typedAddition[candidateAdditionKey{
		Vendor:  vendor,
		PkgName: pkgName,
	}]; ok {
		vendors = append(vendors, additions.AdditionalVendors...)
	}

	if additions, ok := typedAddition[candidateAdditionKey{
		PkgName: pkgName,
	}]; ok {
		vendors = append(vendors, additions.AdditionalVendors...)
	}

	if additions, ok := typedAddition[candidateAdditionKey{
		Vendor: vendor,
	}]; ok {
		vendors = append(vendors, additions.AdditionalVendors...)
	}

	return vendors
}

// additionalProducts(type, product)
func additionalProducts(allAdditions map[pkg.Type]map[candidateAdditionKey]candidateAddition, ty pkg.Type, pkgName string) (products []string) {
	// TODO: rename
	typedAddition, ok := allAdditions[ty]
	if !ok {
		return nil
	}

	if additions, ok := typedAddition[candidateAdditionKey{
		PkgName: pkgName,
	}]; ok {
		products = append(products, additions.AdditionalProducts...)
	}

	return products
}

func (s candidatesByPackageType) getCandidates(t pkg.Type, key string) []string {
	if _, ok := s[t]; !ok {
		return nil
	}
	value, ok := s[t][key]
	if !ok {
		return nil
	}

	return value
}
