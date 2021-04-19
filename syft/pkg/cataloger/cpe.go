package cataloger

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

// this is functionally equivalent to "*" and consistent with no input given (thus easier to test)
const any = ""

// this is a static mapping of known package names (keys) to official cpe names for each package
type candidateStore map[pkg.Type]map[string][]string

var productCandidatesByPkgType = candidateStore{
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

func (s candidateStore) getCandidates(t pkg.Type, key string) []string {
	if _, ok := s[t]; !ok {
		return nil
	}
	value, ok := s[t][key]
	if !ok {
		return nil
	}

	return value
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

// generatePackageCPEs Create a list of CPEs, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func generatePackageCPEs(p pkg.Package) []pkg.CPE {
	targetSws := candidateTargetSoftwareAttrs(p)
	vendors := candidateVendors(p)
	products := candidateProducts(p)

	keys := internal.NewStringSet()
	cpes := make([]pkg.CPE, 0)
	for _, product := range products {
		for _, vendor := range append([]string{any}, vendors...) {
			for _, targetSw := range append([]string{any}, targetSws...) {
				// prevent duplicate entries...
				key := fmt.Sprintf("%s|%s|%s|%s", product, vendor, p.Version, targetSw)
				if keys.Contains(key) {
					continue
				}
				keys.Add(key)

				// add a new entry...
				c := newCPE(product, vendor, p.Version, targetSw)
				cpes = append(cpes, c)
			}
		}
	}

	sort.Sort(ByCPESpecificity(cpes))

	return cpes
}

func candidateTargetSoftwareAttrs(p pkg.Package) []string {
	// TODO: would be great to allow these to be overridden by user data/config
	var targetSw []string
	switch p.Language {
	case pkg.Java:
		targetSw = append(targetSw, candidateTargetSoftwareAttrsForJava(p)...)
	case pkg.JavaScript:
		targetSw = append(targetSw, "node.js", "nodejs")
	case pkg.Ruby:
		targetSw = append(targetSw, "ruby", "rails")
	case pkg.Python:
		targetSw = append(targetSw, "python")
	}

	return targetSw
}

func candidateTargetSoftwareAttrsForJava(p pkg.Package) []string {
	// Use the more specific indicator if available
	if p.Type == pkg.JenkinsPluginPkg {
		return []string{"jenkins", "cloudbees_jenkins"}
	}

	return []string{"java", "maven"}
}

func candidateVendors(p pkg.Package) []string {
	// TODO: Confirm whether using products as vendors is helpful to the matching process
	vendors := candidateProducts(p)

	switch p.Language {
	case pkg.Python:
		vendors = append(vendors, fmt.Sprintf("python-%s", p.Name))
		if strings.Contains(p.Name, "-") {
			vendors = append(vendors, fmt.Sprintf("python_%s", strings.ReplaceAll(p.Name, "-", "_")))
		} else {
			vendors = append(vendors, fmt.Sprintf("python_%s", p.Name))
		}
	case pkg.Java:
		if p.MetadataType == pkg.JavaMetadataType {
			vendors = append(vendors, candidateVendorsForJava(p)...)
		}
	}
	return vendors
}

func candidateProducts(p pkg.Package) []string {
	products := []string{p.Name}

	if p.Language == pkg.Java {
		products = append(products, candidateProductsForJava(p)...)
	}

	for _, prod := range products {
		if strings.Contains(prod, "-") {
			products = append(products, strings.ReplaceAll(prod, "-", "_"))
		}
	}

	// return any known product name swaps prepended to the results
	return append(productCandidatesByPkgType.getCandidates(p.Type, p.Name), products...)
}

func candidateProductsForJava(p pkg.Package) []string {
	if product, _ := productAndVendorFromPomPropertiesGroupID(p); product != "" {
		return []string{product}
	}

	return nil
}

func candidateVendorsForJava(p pkg.Package) []string {
	if _, vendor := productAndVendorFromPomPropertiesGroupID(p); vendor != "" {
		return []string{vendor}
	}

	return nil
}

func productAndVendorFromPomPropertiesGroupID(p pkg.Package) (string, string) {
	groupID := groupIDFromPomProperties(p)
	if !shouldConsiderGroupID(groupID) {
		return "", ""
	}

	if !hasAnyOfPrefixes(groupID, "com", "org") {
		return "", ""
	}

	fields := strings.Split(groupID, ".")
	if len(fields) < 3 {
		return "", ""
	}

	product := fields[2]
	vendor := fields[1]
	return product, vendor
}

func groupIDFromPomProperties(p pkg.Package) string {
	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	if !ok {
		return ""
	}

	if metadata.PomProperties == nil {
		return ""
	}

	return metadata.PomProperties.GroupID
}

func shouldConsiderGroupID(groupID string) bool {
	if groupID == "" {
		return false
	}

	excludedGroupIDs := []string{
		pkg.PomPropertiesGroupIDJiraPlugins,
		pkg.PomPropertiesGroupIDJenkinsPlugins,
	}

	for _, excludedGroupID := range excludedGroupIDs {
		if groupID == excludedGroupID {
			return false
		}
	}

	return true
}

func hasAnyOfPrefixes(input string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(input, prefix) {
			return true
		}
	}

	return false
}
