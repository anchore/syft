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
		targetSw = append(targetSw, "java", "maven")
	case pkg.JavaScript:
		targetSw = append(targetSw, "node.js", "nodejs")
	case pkg.Ruby:
		targetSw = append(targetSw, "ruby", "rails")
	case pkg.Python:
		targetSw = append(targetSw, "python")
	}

	if p.Type == pkg.JenkinsPluginPkg {
		targetSw = append(targetSw, "jenkins", "cloudbees_jenkins")
	}

	return targetSw
}

func candidateVendors(p pkg.Package) []string {
	vendors := candidateProducts(p)
	switch p.Language {
	case pkg.Python:
		vendors = append(vendors, fmt.Sprintf("python-%s", p.Name))
	case pkg.Java:
		if p.MetadataType == pkg.JavaMetadataType {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok && metadata.PomProperties != nil {
				// derive the vendor from the groupID (e.g. org.sonatype.nexus --> sonatype)
				if strings.HasPrefix(metadata.PomProperties.GroupID, "org.") || strings.HasPrefix(metadata.PomProperties.GroupID, "com.") {
					fields := strings.Split(metadata.PomProperties.GroupID, ".")
					if len(fields) >= 3 {
						vendors = append(vendors, fields[1])
					}
				}
			}
		}
	}
	return vendors
}

func candidateProducts(p pkg.Package) []string {
	var products = []string{p.Name}

	if p.Language == pkg.Java {
		if p.MetadataType == pkg.JavaMetadataType {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok && metadata.PomProperties != nil {
				// derive the product from the groupID (e.g. org.sonatype.nexus --> nexus)
				if strings.HasPrefix(metadata.PomProperties.GroupID, "org.") || strings.HasPrefix(metadata.PomProperties.GroupID, "com.") {
					fields := strings.Split(metadata.PomProperties.GroupID, ".")
					if len(fields) >= 3 {
						products = append(products, fields[2])
					}
				}
			}
		}
	}

	// return any known product name swaps prepended to the results
	return append(productCandidatesByPkgType.getCandidates(p.Type, p.Name), products...)
}
