package main

import (
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate/dictionary"
)

func generateIndexedDictionaryJSON(rawGzipData io.Reader) ([]byte, error) {
	gzipReader, err := gzip.NewReader(rawGzipData)
	if err != nil {
		return nil, fmt.Errorf("unable to decompress CPE dictionary: %w", err)
	}
	defer gzipReader.Close()

	// Read XML data
	data, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("unable to read CPE dictionary: %w", err)
	}

	// Unmarshal XML
	var cpeList CpeList
	if err := xml.Unmarshal(data, &cpeList); err != nil {
		return nil, fmt.Errorf("unable to unmarshal CPE dictionary XML: %w", err)
	}

	// Filter out data that's not applicable here
	cpeList = filterCpeList(cpeList)

	// Create indexed dictionary to help with looking up CPEs
	indexedDictionary := indexCPEList(cpeList)

	// Convert to JSON
	jsonData, err := json.MarshalIndent(indexedDictionary, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unable to marshal CPE dictionary to JSON: %w", err)
	}
	return jsonData, nil
}

// filterCpeList removes CPE items that are not applicable to software packages.
func filterCpeList(cpeList CpeList) CpeList {
	var processedCpeList CpeList

	for _, cpeItem := range cpeList.CpeItems {
		// Skip CPE items that don't have any references.
		if len(cpeItem.References.Reference) == 0 {
			continue
		}

		// Skip CPE items where the CPE URI doesn't meet our criteria.
		parsedName, err := wfn.Parse(cpeItem.Name)
		if err != nil {
			log.Printf("unable to parse CPE URI %q: %s", cpeItem.Name, err)
			continue
		}

		if slices.Contains([]string{"h", "o"}, parsedName.Part) {
			continue
		}

		normalizedName := normalizeCPE(parsedName).BindToURI()
		cpeItem.Name = normalizedName

		cpeName := cpeItem.Cpe23Item.Name
		if cpeItem.Cpe23Item.Deprecation.DeprecatedBy.Name != "" {
			cpeName = cpeItem.Cpe23Item.Deprecation.DeprecatedBy.Name
		}

		parsedCPE, err := wfn.Parse(cpeName)
		if err != nil {
			log.Printf("unable to parse CPE value %q: %s", cpeName, err)
			continue
		}

		cpeItem.Cpe23Item.Name = normalizeCPE(parsedCPE).BindToFmtString()

		processedCpeList.CpeItems = append(processedCpeList.CpeItems, cpeItem)
	}

	return processedCpeList
}

// normalizeCPE removes the version and update parts of CPE Attributes.
func normalizeCPE(cpe *wfn.Attributes) *wfn.Attributes {
	cpeCopy := *cpe

	cpeCopy.Version = ""
	cpeCopy.Update = ""

	return &cpeCopy
}

const (
	prefixForNPMPackages                   = "https://www.npmjs.com/package/"
	prefixForRubyGems                      = "https://rubygems.org/gems/"
	prefixForRubyGemsHTTP                  = "http://rubygems.org/gems/"
	prefixForNativeRubyGems                = "https://github.com/ruby/"
	prefixForPyPIPackages                  = "https://pypi.org/project/"
	prefixForJenkinsPlugins                = "https://plugins.jenkins.io/"
	prefixForJenkinsPluginsGitHub          = "https://github.com/jenkinsci/"
	prefixForRustCrates                    = "https://crates.io/crates/"
	prefixForPHPPear                       = "https://pear.php.net/"
	prefixForPHPPearHTTP                   = "http://pear.php.net/"
	prefixForPHPPecl                       = "https://pecl.php.net/"
	prefixForPHPPeclHTTP                   = "http://pecl.php.net/"
	prefixForPHPComposer                   = "https://packagist.org/packages/"
	prefixForGoModules                     = "https://pkg.go.dev/"
	prefixForWordpressPlugins              = "https://wordpress.org/plugins/"
	prefixForWordpressPluginsTracBrowser   = "https://plugins.trac.wordpress.org/browser/"
	prefixForWordpressPluginsTracLog       = "https://plugins.trac.wordpress.org/log/"
	prefixForWordpressPluginsGitHubArchive = "https://github.com/wp-plugins/"
	prefixForWordpressPluginsWordfence     = "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
	prefixForWordpressThemes               = "https://wordpress.org/themes/"
	prefixForWordpressThemesTracBrowser    = "https://themes.trac.wordpress.org/browser/"
	prefixForWordpressThemesTracLog        = "https://themes.trac.wordpress.org/log/"
	prefixForWordpressThemesWordfence      = "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/"
)

// indexCPEList creates an index of CPEs by ecosystem.
func indexCPEList(list CpeList) *dictionary.Indexed {
	indexed := &dictionary.Indexed{
		EcosystemPackages: make(map[string]dictionary.Packages),
	}

	for _, cpeItem := range list.CpeItems {
		cpeItemName := cpeItem.Cpe23Item.Name

		for _, reference := range cpeItem.References.Reference {
			ref := reference.Href

			switch {
			case strings.HasPrefix(ref, prefixForNPMPackages):
				addEntryForNPMPackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForRubyGems), strings.HasPrefix(ref, prefixForRubyGemsHTTP):
				addEntryForRubyGem(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForNativeRubyGems):
				addEntryForNativeRubyGem(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForPyPIPackages):
				addEntryForPyPIPackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForJenkinsPluginsGitHub):
				// It _might_ be a jenkins plugin!
				addEntryForJenkinsPluginGitHub(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForJenkinsPlugins):
				addEntryForJenkinsPlugin(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForRustCrates):
				addEntryForRustCrate(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForPHPPear), strings.HasPrefix(ref, prefixForPHPPearHTTP):
				addEntryForPHPPearPackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForPHPPecl), strings.HasPrefix(ref, prefixForPHPPeclHTTP):
				addEntryForPHPPeclPackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForPHPComposer):
				addEntryForPHPComposerPackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForGoModules):
				addEntryForGoModulePackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForWordpressPlugins), strings.HasPrefix(ref, prefixForWordpressPluginsTracBrowser), strings.HasPrefix(ref, prefixForWordpressPluginsTracLog), strings.HasPrefix(ref, prefixForWordpressPluginsGitHubArchive), strings.HasPrefix(ref, prefixForWordpressPluginsWordfence):
				addEntryForWordpressPlugin(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForWordpressThemes), strings.HasPrefix(ref, prefixForWordpressThemesTracBrowser), strings.HasPrefix(ref, prefixForWordpressThemesTracLog), strings.HasPrefix(ref, prefixForWordpressThemesWordfence):
				addEntryForWordpressTheme(indexed, ref, cpeItemName)
			}
		}
	}

	return indexed
}

func updateIndex(indexed *dictionary.Indexed, ecosystem string, pkgName string, cpe string) {
	if _, exists := indexed.EcosystemPackages[ecosystem]; !exists {
		indexed.EcosystemPackages[ecosystem] = make(dictionary.Packages)
	}

	if indexed.EcosystemPackages[ecosystem][pkgName] == nil {
		indexed.EcosystemPackages[ecosystem][pkgName] = dictionary.NewSet()
	}

	indexed.EcosystemPackages[ecosystem][pkgName].Add(cpe)
}

func addEntryForWordpressPlugin(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForWordpressPlugins)
	ref = strings.TrimPrefix(ref, prefixForWordpressPluginsTracBrowser)
	ref = strings.TrimPrefix(ref, prefixForWordpressPluginsTracLog)
	ref = strings.TrimPrefix(ref, prefixForWordpressPluginsGitHubArchive)
	ref = strings.TrimPrefix(ref, prefixForWordpressPluginsWordfence)
	ref = strings.Split(ref, "?")[0]
	ref = strings.Split(ref, "/")[0]
	if ref == "" {
		return
	}

	updateIndex(indexed, dictionary.EcosystemWordpressPlugins, ref, cpeItemName)
}

func addEntryForWordpressTheme(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForWordpressThemes)
	ref = strings.TrimPrefix(ref, prefixForWordpressThemesTracBrowser)
	ref = strings.TrimPrefix(ref, prefixForWordpressThemesTracLog)
	ref = strings.TrimPrefix(ref, prefixForWordpressThemesWordfence)
	ref = strings.Split(ref, "?")[0]
	ref = strings.Split(ref, "/")[0]
	if ref == "" {
		return
	}

	updateIndex(indexed, dictionary.EcosystemWordpressThemes, ref, cpeItemName)
}

func addEntryForRustCrate(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForRustCrates)
	ref = strings.Split(ref, "/")[0]

	updateIndex(indexed, dictionary.EcosystemRustCrates, ref, cpeItemName)
}

func addEntryForJenkinsPluginGitHub(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForJenkinsPluginsGitHub)
	ref = strings.Split(ref, "/")[0]

	if !strings.HasSuffix(ref, "-plugin") {
		// It's not a jenkins plugin!
		return
	}

	ref = strings.TrimSuffix(ref, "-plugin")
	updateIndex(indexed, dictionary.EcosystemJenkinsPlugins, ref, cpeItemName)
}

func addEntryForJenkinsPlugin(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForJenkinsPlugins)
	ref = strings.Split(ref, "/")[0]

	if ref == "" {
		return
	}

	updateIndex(indexed, dictionary.EcosystemJenkinsPlugins, ref, cpeItemName)
}

func addEntryForPyPIPackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForPyPIPackages)
	ref = strings.Split(ref, "/")[0]

	updateIndex(indexed, dictionary.EcosystemPyPI, ref, cpeItemName)
}

func addEntryForNativeRubyGem(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForNativeRubyGems)
	ref = strings.Split(ref, "/")[0]

	updateIndex(indexed, dictionary.EcosystemRubyGems, ref, cpeItemName)
}

func addEntryForRubyGem(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForRubyGems)
	ref = strings.TrimPrefix(ref, prefixForRubyGemsHTTP)
	ref = strings.Split(ref, "/")[0]

	updateIndex(indexed, dictionary.EcosystemRubyGems, ref, cpeItemName)
}

func addEntryForNPMPackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.Split(ref, "/v/")[0]
	ref = strings.Split(ref, "?")[0]
	ref = strings.TrimPrefix(ref, prefixForNPMPackages)

	updateIndex(indexed, dictionary.EcosystemNPM, ref, cpeItemName)
}

func phpExtensionPackageFromURLFragment(ref string) string {
	if strings.HasPrefix(ref, "package/") { // package/HTML_QuickForm/download
		ref = strings.TrimPrefix(ref, "package/")
		components := strings.Split(ref, "/")

		if len(components) < 1 {
			return ""
		}

		ref = components[0]
	} else if strings.Contains(ref, "?package=") { // package-changelog.php?package=xhprof&amp;release=0.9.4
		components := strings.Split(ref, "?package=")

		if len(components) < 2 {
			return ""
		}

		components = strings.Split(components[1], "&")
		if len(components) < 2 {
			return ""
		}

		ref = components[0]
	}

	return ref
}

func addEntryForPHPPearPackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	ref = strings.TrimPrefix(ref, prefixForPHPPear)
	ref = strings.TrimPrefix(ref, prefixForPHPPearHTTP)
	ref = phpExtensionPackageFromURLFragment(ref)

	if ref == "" {
		return
	}

	updateIndex(indexed, dictionary.EcosystemPHPPear, ref, cpeItemName)
}

func addEntryForPHPPeclPackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	ref = strings.TrimPrefix(ref, prefixForPHPPecl)
	ref = strings.TrimPrefix(ref, prefixForPHPPeclHTTP)
	ref = phpExtensionPackageFromURLFragment(ref)

	if ref == "" {
		return
	}

	updateIndex(indexed, dictionary.EcosystemPHPPecl, ref, cpeItemName)
}

func addEntryForPHPComposerPackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForPHPComposer)
	components := strings.Split(ref, "/")

	if len(components) < 2 {
		return
	}

	ref = components[0] + "/" + components[1]

	updateIndex(indexed, dictionary.EcosystemPHPComposer, ref, cpeItemName)
}

func addEntryForGoModulePackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.Split(ref, "?")[0]
	ref = strings.TrimPrefix(ref, prefixForGoModules)

	// Ignore the vulnerability reports endpoints
	if strings.HasPrefix(ref, "vuln/") {
		return
	}

	updateIndex(indexed, dictionary.EcosystemGoModules, ref, cpeItemName)
}
