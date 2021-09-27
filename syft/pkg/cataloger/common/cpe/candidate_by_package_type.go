package cpe

import (
	"github.com/anchore/syft/syft/pkg"
)

var defaultCandidateAdditions = map[pkg.Type]map[candidateAdditionKey]candidateAddition{
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
		candidateAdditionKey{
			PkgName: "hapi",
		}: {
			AdditionalProducts: []string{"hapi_server_framework"},
		},
		candidateAdditionKey{
			PkgName: "handlebars.js",
		}: {
			AdditionalProducts: []string{"handlebars"},
		},
		candidateAdditionKey{
			PkgName: "is-my-json-valid",
		}: {
			AdditionalProducts: []string{"is_my_json_valid"},
		},
		candidateAdditionKey{
			PkgName: "mustache",
		}: {
			AdditionalProducts: []string{"mustache.js"},
		},
	},
	pkg.GemPkg: {
		candidateAdditionKey{
			PkgName: "Arabic-Prawn",
		}: {
			AdditionalProducts: []string{"arabic_prawn"},
		},
		candidateAdditionKey{
			PkgName: "bio-basespace-sdk",
		}: {
			AdditionalProducts: []string{"basespace_ruby_sdk"},
		},
		candidateAdditionKey{
			PkgName: "cremefraiche",
		}: {
			AdditionalProducts: []string{"creme_fraiche"},
		},
		candidateAdditionKey{
			PkgName: "html-sanitizer",
		}: {
			AdditionalProducts: []string{"html_sanitizer"},
		},
		candidateAdditionKey{
			PkgName: "sentry-raven",
		}: {
			AdditionalProducts: []string{"raven-ruby"},
		},
		candidateAdditionKey{
			PkgName: "RedCloth",
		}: {
			AdditionalProducts: []string{"redcloth_library"},
		},
		candidateAdditionKey{
			PkgName: "VladTheEnterprising",
		}: {
			AdditionalProducts: []string{"vladtheenterprising"},
		},
		candidateAdditionKey{
			PkgName: "yajl-ruby",
		}: {
			AdditionalProducts: []string{"yajl-ruby_gem"},
		},
	},
	pkg.PythonPkg: {
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

// AdditionalVendors(type, product, vendor)
func findAdditionalVendors(allAdditions map[pkg.Type]map[candidateAdditionKey]candidateAddition, ty pkg.Type, pkgName, vendor string) (vendors []string) {
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

// findAdditionalProducts(type, product)
func findAdditionalProducts(allAdditions map[pkg.Type]map[candidateAdditionKey]candidateAddition, ty pkg.Type, pkgName string) (products []string) {
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
