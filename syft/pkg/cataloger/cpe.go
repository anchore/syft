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

var (
	forbiddenProductGroupIDFields = strset.New("plugin", "plugins", "client")
	forbiddenVendorGroupIDFields  = strset.New("plugin", "plugins")
	javaManifestGroupIDFields     = []string{
		"Extension-Name",
		"Automatic-Module-Name",
		"Specification-Vendor",
		"Implementation-Vendor",
		"Bundle-SymbolicName",
		"Implementation-Vendor-Id",
		"Package",
		"Implementation-Title",
		"Main-Class",
		"Bundle-Activator",
	}
	javaManifestNameFields = []string{
		"Specification-Vendor",
		"Implementation-Vendor",
	}
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

// generatePackageCPEs Create a list of CPEs, trying to guess the vendor, product tuple. We should be trying to
// generate the minimal set of representative CPEs, which implies that optional fields should not be included
// (such as target SW).
func generatePackageCPEs(p pkg.Package) []pkg.CPE {
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
	cpes = filterCPEs(cpes, p, cpeFilters...)

	sort.Sort(ByCPESpecificity(cpes))

	return cpes
}

func candidateVendors(p pkg.Package) []string {
	// in ecosystems where the packaging metadata does not have a clear field to indicate a vendor (or a field that
	// could be interpreted indirectly as such) the project name tends to be a common stand in. Examples of this
	// are the elasticsearch gem, xstream jar, and rack gem... all of these cases you can find vulnerabilities
	// with CPEs where the vendor is the product name and doesn't appear to be derived from any available package
	// metadata.
	vendors := newCPRFieldCandidateSet(candidateProducts(p)...)

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
	products := newCPRFieldCandidateSet(p.Name)

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

func candidateVendorsForJava(p pkg.Package) *cpeFieldCandidateSet {
	gidVendors := vendorsFromGroupIDs(groupIDsFromJavaPackage(p))
	nameVendors := vendorsFromJavaManifestNames(p)
	return newCPRFieldCandidateFromSets(gidVendors, nameVendors)
}

func vendorsFromJavaManifestNames(p pkg.Package) *cpeFieldCandidateSet {
	vendors := newCPRFieldCandidateSet()

	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	if !ok {
		return vendors
	}

	if metadata.Manifest == nil {
		return vendors
	}

	for _, name := range javaManifestNameFields {
		if value, exists := metadata.Manifest.Main[name]; exists {
			if !startsWithDomain(value) {
				vendors.add(cpeFieldCandidate{
					value:                 normalizeName(value),
					disallowSubSelections: true,
				})
			}
		}
		for _, section := range metadata.Manifest.NamedSections {
			if value, exists := section[name]; exists {
				if !startsWithDomain(value) {
					vendors.add(cpeFieldCandidate{
						value:                 normalizeName(value),
						disallowSubSelections: true,
					})
				}
			}
		}
	}

	return vendors
}

func vendorsFromGroupIDs(groupIDs []string) *cpeFieldCandidateSet {
	vendors := newCPRFieldCandidateSet()
	for _, groupID := range groupIDs {
		for i, field := range strings.Split(groupID, ".") {
			field = strings.TrimSpace(field)

			if len(field) == 0 {
				continue
			}

			if forbiddenVendorGroupIDFields.Has(strings.ToLower(field)) {
				continue
			}

			if i == 0 {
				continue
			}

			// e.g. jenkins-ci -> [jenkins-ci, jenkins]
			for _, value := range generateSubSelections(field) {
				vendors.add(cpeFieldCandidate{
					value:                 value,
					disallowSubSelections: true,
				})
			}
		}
	}

	return vendors
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
			if forbiddenProductGroupIDFields.Has(strings.ToLower(field)) {
				continue
			}

			if i <= 1 {
				continue
			}

			// umbrella projects tend to have sub components that either start or end with the project name. We expect
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
	for _, name := range javaManifestGroupIDFields {
		if value, exists := manifest.Main[name]; exists {
			if startsWithDomain(value) {
				groupIDs = append(groupIDs, value)
			}
		}
		for _, section := range manifest.NamedSections {
			if value, exists := section[name]; exists {
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

func addAllSubSelections(set *cpeFieldCandidateSet) {
	for _, candidate := range set.values(filterCandidatesBySubselection) {
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

func addDelimiterVariations(fields *cpeFieldCandidateSet) {
	for _, candidate := range fields.list(filterCandidatesByDelimiterVariations) {
		field := candidate.value
		hasHyphen := strings.Contains(field, "-")
		hasUnderscore := strings.Contains(field, "_")

		if hasHyphen {
			// provide variations of hyphen candidates with an underscore
			newValue := strings.ReplaceAll(field, "-", "_")
			candidate.value = newValue
			fields.add(candidate)
		}

		if hasUnderscore {
			// provide variations of underscore candidates with a hyphen
			newValue := strings.ReplaceAll(field, "_", "-")
			candidate.value = newValue
			fields.add(candidate)
		}
	}
}

func candidateVendorsForRPM(p pkg.Package) *cpeFieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.RpmdbMetadata)
	if !ok {
		return nil
	}

	vendors := newCPRFieldCandidateSet()

	if metadata.Vendor != "" {
		vendors.add(cpeFieldCandidate{
			value:                 normalizeTitle(metadata.Vendor),
			disallowSubSelections: true,
		})
	}

	return vendors
}

func candidateVendorsForPython(p pkg.Package) *cpeFieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.PythonPackageMetadata)
	if !ok {
		return nil
	}

	vendors := newCPRFieldCandidateSet()

	if metadata.Author != "" {
		vendors.add(cpeFieldCandidate{
			value:                       normalizeName(metadata.Author),
			disallowSubSelections:       true,
			disallowDelimiterVariations: true,
		})
	}

	if metadata.AuthorEmail != "" {
		vendors.add(cpeFieldCandidate{
			value:                 normalizeName(stripEmailSuffix(metadata.AuthorEmail)),
			disallowSubSelections: true,
		})
	}

	return vendors
}

func candidateVendorsForRuby(p pkg.Package) *cpeFieldCandidateSet {
	metadata, ok := p.Metadata.(pkg.GemMetadata)
	if !ok {
		return nil
	}

	vendors := newCPRFieldCandidateSet()

	for _, author := range metadata.Authors {
		// author could be a name or an email
		vendors.add(cpeFieldCandidate{
			value:                 normalizeName(stripEmailSuffix(author)),
			disallowSubSelections: true,
		})
	}
	return vendors
}

func stripEmailSuffix(email string) string {
	return strings.Split(email, "@")[0]
}

func normalizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	for _, value := range []string{"-", " ", "."} {
		name = strings.ReplaceAll(name, value, "_")
	}
	return strings.TrimPrefix(name, "the_")
}

func normalizeTitle(name string) string {
	name = strings.Split(name, ",")[0]
	name = strings.TrimSpace(strings.ToLower(name))
	return strings.ReplaceAll(name, " ", "")
}
