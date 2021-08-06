package cataloger

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

var domains = []string{
	"com",
	"org",
	"net",
	"io",
}

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

// this is a static mapping of known package names (keys) to official cpe names for each package
type candidateStore map[pkg.Type]map[string][]string

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

func filterCPEs(cpes []pkg.CPE, p pkg.Package, filters ...filterFn) (result []pkg.CPE) {
cpeLoop:
	for _, cpe := range cpes {
		for _, fn := range filters {
			if fn(cpe, p) {
				continue cpeLoop
			}
		}
		// all filter functions passed on filtering this CPE
		result = append(result, cpe)
	}
	return result
}

// generatePackageCPEs Create a list of CPEs, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func generatePackageCPEs(p pkg.Package) []pkg.CPE {
	targetSws := candidateTargetSoftwareAttrs(p)
	vendors := candidateVendors(p)
	products := candidateProducts(p)

	if len(products) == 0 {
		return nil
	}

	keys := internal.NewStringSet()
	cpes := make([]pkg.CPE, 0)
	for _, product := range products {
		for _, vendor := range vendors {
			for _, targetSw := range append([]string{wfn.Any}, targetSws...) {
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

	// filter out any known combinations that don't accurately represent this package
	cpes = filterCPEs(cpes, p, cpeFilters...)

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
	case pkg.Go:
		targetSw = append(targetSw, "go", "golang")
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
	vendors := strset.New(candidateProducts(p)...)

	switch p.Language {
	case pkg.Ruby:
		vendors.Add("ruby-lang")
	case pkg.Java:
		if p.MetadataType == pkg.JavaMetadataType {
			vendors.Add(candidateVendorsForJava(p)...)
		}
	case pkg.Go:
		// replace all candidates with only the golang-specific helper
		vendors.Clear()

		vendor := candidateVendorForGo(p.Name)
		if vendor != "" {
			vendors.Add(vendor)
		}
	}

	// try swapping hyphens for underscores, vice versa, and removing separators altogether
	addSeparatorVariations(vendors)

	// generate sub-selections of each candidate based on separators (e.g. jenkins-ci -> [jenkins, jenkins-ci])
	return generateAllSubSelections(vendors.List())
}

func candidateProducts(p pkg.Package) []string {
	products := strset.New(p.Name)

	switch {
	case p.Language == pkg.Python:
		if !strings.HasPrefix(p.Name, "python") {
			products.Add("python-" + p.Name)
		}
	case p.Language == pkg.Java || p.MetadataType == pkg.JavaMetadataType:
		products.Add(candidateProductsForJava(p)...)
	case p.Language == pkg.Go:
		// replace all candidates with only the golang-specific helper
		products.Clear()

		prod := candidateProductForGo(p.Name)
		if prod != "" {
			products.Add(prod)
		}
	}

	// try swapping hyphens for underscores, vice versa, and removing separators altogether
	addSeparatorVariations(products)

	// prepend any known product name swaps prepended to the results
	return append(productCandidatesByPkgType.getCandidates(p.Type, p.Name), products.List()...)
}

// candidateProductForGo attempts to find a single product name in a best-effort attempt. This implementation prefers
// to return no vendor over returning potentially nonsensical results.
func candidateProductForGo(name string) string {
	// note: url.Parse requires a scheme for correct processing, which a golang module will not have, so one is provided.
	u, err := url.Parse("http://" + name)
	if err != nil {
		return ""
	}

	cleanPath := strings.Trim(u.Path, "/")
	pathElements := strings.Split(cleanPath, "/")

	switch u.Host {
	case "golang.org", "gopkg.in":
		return cleanPath
	case "google.golang.org":
		return pathElements[0]
	}

	if len(pathElements) < 2 {
		return ""
	}

	return pathElements[1]
}

// candidateVendorForGo attempts to find a single vendor name in a best-effort attempt. This implementation prefers
// to return no vendor over returning potentially nonsensical results.
func candidateVendorForGo(name string) string {
	// note: url.Parse requires a scheme for correct processing, which a golang module will not have, so one is provided.
	u, err := url.Parse("http://" + name)
	if err != nil {
		return ""
	}

	cleanPath := strings.Trim(u.Path, "/")

	switch u.Host {
	case "google.golang.org":
		return "google"
	case "golang.org":
		return "golang"
	case "gopkg.in":
		return ""
	}

	pathElements := strings.Split(cleanPath, "/")
	if len(pathElements) < 2 {
		return ""
	}
	return pathElements[0]
}

func candidateProductsForJava(p pkg.Package) []string {
	return productsFromArtifactAndGroupIDs(artifactIDFromJavaPackage(p), groupIDsFromJavaPackage(p))
}

func candidateVendorsForJava(p pkg.Package) []string {
	return vendorsFromGroupIDs(groupIDsFromJavaPackage(p))
}

func vendorsFromGroupIDs(groupIDs []string) []string {
	vendors := strset.New()
	for _, groupID := range groupIDs {
		for i, field := range strings.Split(groupID, ".") {
			field = strings.TrimSpace(field)

			if len(field) == 0 {
				continue
			}

			if internal.ContainsString(strings.ToLower(field), []string{"plugin", "plugins"}) {
				continue
			}

			if i == 0 {
				continue
			}

			// e.g. jenkins-ci -> [jenkins-ci, jenkins]
			vendors.Add(generateSubSelections(field)...)
		}
	}

	return vendors.List()
}

func productsFromArtifactAndGroupIDs(artifactID string, groupIDs []string) []string {
	products := strset.New()
	if artifactID != "" {
		products.Add(artifactID)
	}

	for _, groupID := range groupIDs {
		isPlugin := strings.Contains(artifactID, "plugin") || strings.Contains(groupID, "plugin")

		for i, field := range strings.Split(groupID, ".") {
			field = strings.TrimSpace(field)

			if len(field) == 0 {
				continue
			}

			// don't add this field as a name if the name is implying the package is a plugin or client
			if internal.ContainsString(strings.ToLower(field), []string{"plugin", "plugins", "client"}) {
				continue
			}

			if i <= 1 {
				continue
			}

			// umbrella projects tend to have sub components that either start or end with the project name. We want
			// to identify fields that may represent the umbrella project, and not fields that indicate auxiliary
			// information about the package.
			couldBeProjectName := strings.HasPrefix(artifactID, field) || strings.HasSuffix(artifactID, field)
			if artifactID == "" || (couldBeProjectName && !isPlugin) {
				products.Add(field)
			}
		}
	}

	return products.List()
}

func artifactIDFromJavaPackage(p pkg.Package) string {
	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	if !ok {
		return ""
	}

	if metadata.PomProperties == nil {
		return ""
	}

	artifactID := strings.TrimSpace(metadata.PomProperties.ArtifactID)
	if startsWithDomain(artifactID) && len(strings.Split(artifactID, ".")) > 1 {
		// there is a strong indication that the artifact ID is really a group ID, don't use it
		return ""
	}
	return artifactID
}

func groupIDsFromJavaPackage(p pkg.Package) (groupIDs []string) {
	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	if !ok {
		return nil
	}

	groupIDs = append(groupIDs, groupIDsFromPomProperties(metadata.PomProperties)...)
	groupIDs = append(groupIDs, groupIDsFromJavaManifest(metadata.Manifest)...)

	return groupIDs
}

func groupIDsFromPomProperties(properties *pkg.PomProperties) (groupIDs []string) {
	if properties == nil {
		return nil
	}

	if startsWithDomain(properties.GroupID) {
		groupIDs = append(groupIDs, strings.TrimSpace(properties.GroupID))
	}

	// sometimes the publisher puts the group ID in the artifact ID field unintentionally
	if startsWithDomain(properties.ArtifactID) && len(strings.Split(properties.ArtifactID, ".")) > 1 {
		// there is a strong indication that the artifact ID is really a group ID
		groupIDs = append(groupIDs, strings.TrimSpace(properties.ArtifactID))
	}

	return groupIDs
}

func groupIDsFromJavaManifest(manifest *pkg.JavaManifest) (groupIDs []string) {
	if manifest == nil {
		return nil
	}
	// attempt to get group-id-like info from the MANIFEST.MF "Automatic-Module-Name" and "Extension-Name" field.
	// for more info see pkg:maven/commons-io/commons-io@2.8.0 within cloudbees/cloudbees-core-mm:2.263.4.2
	// at /usr/share/jenkins/jenkins.war:WEB-INF/plugins/analysis-model-api.hpi:WEB-INF/lib/commons-io-2.8.0.jar
	// as well as the ant package from cloudbees/cloudbees-core-mm:2.277.2.4-ra.
	for name, value := range manifest.Main {
		value = strings.TrimSpace(value)
		switch name {
		case "Extension-Name", "Automatic-Module-Name":
			if startsWithDomain(value) {
				groupIDs = append(groupIDs, value)
			}
		}
	}
	for _, section := range manifest.NamedSections {
		for name, value := range section {
			value = strings.TrimSpace(value)
			switch name {
			case "Extension-Name", "Automatic-Module-Name":
				if startsWithDomain(value) {
					groupIDs = append(groupIDs, value)
				}
			}
		}
	}
	return groupIDs
}

func startsWithDomain(value string) bool {
	return internal.HasAnyOfPrefixes(value, domains...)
}

func generateAllSubSelections(fields []string) (results []string) {
	for _, field := range fields {
		results = append(results, generateSubSelections(field)...)
	}
	return results
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

func addSeparatorVariations(fields *strset.Set) {
	for _, field := range fields.List() {
		hasHyphen := strings.Contains(field, "-")
		hasUnderscore := strings.Contains(field, "_")

		if hasHyphen {
			// provide variations of hyphen candidates with an underscore
			fields.Add(strings.ReplaceAll(field, "-", "_"))
		}

		if hasUnderscore {
			// provide variations of underscore candidates with a hyphen
			fields.Add(strings.ReplaceAll(field, "_", "-"))
		}
	}
}
