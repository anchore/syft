package cpe

import (
	"github.com/anchore/syft/syft/pkg"
)

type candidateAdditions map[pkg.Type]map[candidateKey]candidateAddition

type candidateComposite struct {
	pkg.Type
	candidateKey
	candidateAddition
}

var candidateComposites = []candidateComposite{
	{
		pkg.JavaPkg,
		candidateKey{PkgName: "springframework"},
		candidateAddition{AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"}},
	},
	{
		pkg.JavaPkg,
		candidateKey{PkgName: "spring-core"},
		candidateAddition{AdditionalProducts: []string{"spring_framework", "springsource_spring_framework"}},
	},
}

func init() {
	defaultCandidateAdditions = buildCandidateLookup(candidateComposites)
}

func buildCandidateLookup(cc []candidateComposite) (ca candidateAdditions) {
	ca = make(map[pkg.Type]map[candidateKey]candidateAddition)
	for _, c := range cc {
		ca[c.Type] = map[candidateKey]candidateAddition{
			c.candidateKey: c.candidateAddition,
		}
	}

	return ca
}

var defaultCandidateAdditions = map[pkg.Type]map[candidateKey]candidateAddition{
	pkg.NpmPkg: {
		candidateKey{
			PkgName: "hapi",
		}: {
			AdditionalProducts: []string{"hapi_server_framework"},
		},
		candidateKey{
			PkgName: "handlebars.js",
		}: {
			AdditionalProducts: []string{"handlebars"},
		},
		candidateKey{
			PkgName: "is-my-json-valid",
		}: {
			AdditionalProducts: []string{"is_my_json_valid"},
		},
		candidateKey{
			PkgName: "mustache",
		}: {
			AdditionalProducts: []string{"mustache.js"},
		},
	},
	pkg.GemPkg: {
		candidateKey{
			PkgName: "Arabic-Prawn",
		}: {
			AdditionalProducts: []string{"arabic_prawn"},
		},
		candidateKey{
			PkgName: "bio-basespace-sdk",
		}: {
			AdditionalProducts: []string{"basespace_ruby_sdk"},
		},
		candidateKey{
			PkgName: "cremefraiche",
		}: {
			AdditionalProducts: []string{"creme_fraiche"},
		},
		candidateKey{
			PkgName: "html-sanitizer",
		}: {
			AdditionalProducts: []string{"html_sanitizer"},
		},
		candidateKey{
			PkgName: "sentry-raven",
		}: {
			AdditionalProducts: []string{"raven-ruby"},
		},
		candidateKey{
			PkgName: "RedCloth",
		}: {
			AdditionalProducts: []string{"redcloth_library"},
		},
		candidateKey{
			PkgName: "VladTheEnterprising",
		}: {
			AdditionalProducts: []string{"vladtheenterprising"},
		},
		candidateKey{
			PkgName: "yajl-ruby",
		}: {
			AdditionalProducts: []string{"yajl-ruby_gem"},
		},
	},
	pkg.PythonPkg: {
		candidateKey{
			PkgName: "python-rrdtool",
		}: {
			AdditionalProducts: []string{"rrdtool"},
		},
	},
}

type candidateKey struct {
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
func findAdditionalVendors(allAdditions map[pkg.Type]map[candidateKey]candidateAddition, ty pkg.Type, pkgName, vendor string) (vendors []string) {
	// TODO: rename
	typedAddition, ok := allAdditions[ty]
	if !ok {
		return nil
	}

	if additions, ok := typedAddition[candidateKey{
		Vendor:  vendor,
		PkgName: pkgName,
	}]; ok {
		vendors = append(vendors, additions.AdditionalVendors...)
	}

	if additions, ok := typedAddition[candidateKey{
		PkgName: pkgName,
	}]; ok {
		vendors = append(vendors, additions.AdditionalVendors...)
	}

	if additions, ok := typedAddition[candidateKey{
		Vendor: vendor,
	}]; ok {
		vendors = append(vendors, additions.AdditionalVendors...)
	}

	return vendors
}

// findAdditionalProducts(type, product)
func findAdditionalProducts(allAdditions map[pkg.Type]map[candidateKey]candidateAddition, ty pkg.Type, pkgName string) (products []string) {
	// TODO: rename
	typedAddition, ok := allAdditions[ty]
	if !ok {
		return nil
	}

	if additions, ok := typedAddition[candidateKey{
		PkgName: pkgName,
	}]; ok {
		products = append(products, additions.AdditionalProducts...)
	}

	return products
}
