package cpe

import (
	"bufio"
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
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

func newCPE(product, vendor, version, targetSW string) wfn.Attributes {
	cpe := *(wfn.NewAttributesWithAny())
	cpe.Part = "a"
	cpe.Product = product
	cpe.Vendor = vendor
	cpe.Version = version
	cpe.TargetSW = targetSW

	return cpe
}

// Generate Create a list of CPEs for a given package, trying to guess the vendor, product tuple. We should be trying to
// generate the minimal set of representative CPEs, which implies that optional fields should not be included
// (such as target SW).
func Generate(p pkg.Package) []pkg.CPE {
	vendors := candidateVendors(p)
	products := candidateProducts(p)

	if len(products) == 0 {
		return nil
	}

	keys := internal.NewStringSet()
	cpes := make([]pkg.CPE, 0)
	for _, product := range products {
		for _, vendor := range vendors {
			// prevent duplicate entries...
			key := fmt.Sprintf("%s|%s|%s", product, vendor, p.Version)
			if keys.Contains(key) {
				continue
			}
			keys.Add(key)

			// add a new entry...
			cpes = append(cpes, newCPE(product, vendor, p.Version, wfn.Any))
		}
	}

	// filter out any known combinations that don't accurately represent this package
	cpes = filter(cpes, p, cpeFilters...)

	sort.Sort(BySpecificity(cpes))

	return cpes
}

func candidateVendors(p pkg.Package) []string {
	// in ecosystems where the packaging metadata does not have a clear field to indicate a vendor (or a field that
	// could be interpreted indirectly as such) the project name tends to be a common stand in. Examples of this
	// are the elasticsearch gem, xstream jar, and rack gem... all of these cases you can find vulnerabilities
	// with CPEs where the vendor is the product name and doesn't appear to be derived from any available package
	// metadata.
	vendors := newFieldCandidateSet(candidateProducts(p)...)

	switch p.Language {
	case pkg.Ruby:
		vendors.addValue("ruby-lang")
	case pkg.Go:
		// replace all candidates with only the golang-specific helper
		vendors.clear()

		vendor := candidateVendorForGo(p.Name)
		if vendor != "" {
			vendors.addValue(vendor)
		}
	}

	// some ecosystems do not have enough metadata to determine the vendor accurately, in which case we selectively
	// allow * as a candidate. Note: do NOT allow Java packages to have * vendors.
	switch p.Language {
	case pkg.Ruby, pkg.JavaScript:
		vendors.addValue("*")
	}

	switch p.MetadataType {
	case pkg.RpmdbMetadataType:
		vendors.union(candidateVendorsForRPM(p))
	case pkg.GemMetadataType:
		vendors.union(candidateVendorsForRuby(p))
	case pkg.PythonPackageMetadataType:
		vendors.union(candidateVendorsForPython(p))
	case pkg.JavaMetadataType:
		vendors.union(candidateVendorsForJava(p))
	}

	// try swapping hyphens for underscores, vice versa, and removing separators altogether
	addDelimiterVariations(vendors)

	// generate sub-selections of each candidate based on separators (e.g. jenkins-ci -> [jenkins, jenkins-ci])
	addAllSubSelections(vendors)

	return vendors.uniqueValues()
}

func candidateProducts(p pkg.Package) []string {
	products := newFieldCandidateSet(p.Name)

	switch {
	case p.Language == pkg.Python:
		if !strings.HasPrefix(p.Name, "python") {
			products.addValue("python-" + p.Name)
		}
	case p.Language == pkg.Java || p.MetadataType == pkg.JavaMetadataType:
		products.addValue(candidateProductsForJava(p)...)
	case p.Language == pkg.Go:
		// replace all candidates with only the golang-specific helper
		products.clear()

		prod := candidateProductForGo(p.Name)
		if prod != "" {
			products.addValue(prod)
		}
	}

	// try swapping hyphens for underscores, vice versa, and removing separators altogether
	addDelimiterVariations(products)

	// prepend any known product names for the given package type and name (note: this is not a replacement)
	return append(productCandidatesByPkgType.getCandidates(p.Type, p.Name), products.uniqueValues()...)
}

func addAllSubSelections(set fieldCandidateSet) {
	for _, candidate := range set.values(filterFieldCandidatesBySubselection) {
		set.addValue(generateSubSelections(candidate)...)
	}
}

// generateSubSelections attempts to split a field by hyphens and underscores and return a list of sensible sub-selections
// that can be used as product or vendor candidates. E.g. jenkins-ci-tools -> [jenkins-ci-tools, jenkins-ci, jenkins].
func generateSubSelections(field string) (results []string) {
	scanner := bufio.NewScanner(strings.NewReader(field))
	scanner.Split(scanByHyphenOrUnderscore)
	var lastToken uint8
	for scanner.Scan() {
		rawCandidate := scanner.Text()
		if len(rawCandidate) == 0 {
			break
		}

		// trim any number of hyphen or underscore that is prefixed/suffixed on the given candidate. Since
		// scanByHyphenOrUnderscore preserves delimiters (hyphens and underscores) they are guaranteed to be at least
		// prefixed.
		candidate := strings.TrimFunc(rawCandidate, trimHyphenOrUnderscore)

		// capture the result (if there is content)
		if len(candidate) > 0 {
			if len(results) > 0 {
				results = append(results, results[len(results)-1]+string(lastToken)+candidate)
			} else {
				results = append(results, candidate)
			}
		}

		// keep track of the trailing separator for the next loop
		lastToken = rawCandidate[len(rawCandidate)-1]
	}
	return results
}

// trimHyphenOrUnderscore is a character filter function for use with strings.TrimFunc in order to remove any hyphen or underscores.
func trimHyphenOrUnderscore(r rune) bool {
	switch r {
	case '-', '_':
		return true
	}
	return false
}

// scanByHyphenOrUnderscore splits on hyphen or underscore and includes the separator in the split
func scanByHyphenOrUnderscore(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "-_"); i >= 0 {
		return i + 1, data[0 : i+1], nil
	}

	if atEOF {
		return len(data), data, nil
	}

	return 0, nil, nil
}

func addDelimiterVariations(fields fieldCandidateSet) {
	for _, candidate := range fields.list(filterFieldCandidatesByDelimiterVariations) {
		field := candidate.value
		hasHyphen := strings.Contains(field, "-")
		hasUnderscore := strings.Contains(field, "_")

		if hasHyphen {
			// provide variations of hyphen candidates with an underscore
			newValue := strings.ReplaceAll(field, "-", "_")
			underscoreCandidate := candidate
			underscoreCandidate.value = newValue
			fields.add(underscoreCandidate)
		}

		if hasUnderscore {
			// provide variations of underscore candidates with a hyphen
			newValue := strings.ReplaceAll(field, "_", "-")
			hyphenCandidate := candidate
			hyphenCandidate.value = newValue
			fields.add(hyphenCandidate)
		}
	}
}
