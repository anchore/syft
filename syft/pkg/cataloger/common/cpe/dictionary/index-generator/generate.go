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

	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe/dictionary"
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

	seen := make(map[string]struct{})

	for _, cpeItem := range cpeList.CpeItems {
		// Skip CPE items that don't have any references.
		if len(cpeItem.References) == 0 {
			continue
		}

		// Skip CPE items where the CPE URI doesn't meet our criteria.
		parsedName, err := wfn.Parse(cpeItem.Name)
		if err != nil {
			log.Printf("unable to parse CPE URI %q: %s", cpeItem.Name, err)
		}

		if slices.Contains([]string{"h", "o"}, parsedName.Part) {
			continue
		}

		normalizedName := normalizeCPE(parsedName).BindToURI()
		if _, ok := seen[normalizedName]; ok {
			continue
		}
		seen[normalizedName] = struct{}{}
		cpeItem.Name = normalizedName

		parsedCPE, err := wfn.Parse(cpeItem.Cpe23Item.Name)
		if err != nil {
			log.Printf("unable to parse CPE value %q: %s", cpeItem.Cpe23Item.Name, err)
		}

		cpeItem.Cpe23Item.Name = normalizeCPE(parsedCPE).BindToFmtString()

		processedCpeList.CpeItems = append(processedCpeList.CpeItems, cpeItem)
	}

	return processedCpeList
}

// normalizeCPE removes the version and update parts of a CPE.
func normalizeCPE(cpe *wfn.Attributes) *wfn.Attributes {
	cpeCopy := *cpe

	cpeCopy.Version = ""
	cpeCopy.Update = ""

	return &cpeCopy
}

const (
	prefixForNPMPackages    = "https://www.npmjs.com/package/"
	prefixForRubyGems       = "https://rubygems.org/gems/"
	prefixForRubyGemsHTTP   = "http://rubygems.org/gems/"
	prefixForNativeRubyGems = "https://github.com/ruby/"
	prefixForPyPIPackages   = "https://pypi.org/project/"
	prefixForJenkinsPlugins = "https://github.com/jenkinsci/"
	prefixForRustCrates     = "https://crates.io/crates/"
)

// indexCPEList creates an index of CPEs by ecosystem.
func indexCPEList(list CpeList) *dictionary.Indexed {
	indexed := &dictionary.Indexed{
		EcosystemPackages: make(map[string]dictionary.Packages),
	}

	for _, cpeItem := range list.CpeItems {
		cpeItemName := cpeItem.Cpe23Item.Name

		for _, reference := range cpeItem.References {
			ref := reference.Reference.Href

			switch {
			case strings.HasPrefix(ref, prefixForNPMPackages):
				addEntryForNPMPackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForRubyGems), strings.HasPrefix(ref, prefixForRubyGemsHTTP):
				addEntryForRubyGem(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForNativeRubyGems):
				addEntryForNativeRubyGem(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForPyPIPackages):
				addEntryForPyPIPackage(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForJenkinsPlugins):
				// It _might_ be a jenkins plugin!
				addEntryForJenkinsPlugin(indexed, ref, cpeItemName)

			case strings.HasPrefix(ref, prefixForRustCrates):
				addEntryForRustCrate(indexed, ref, cpeItemName)
			}
		}
	}

	return indexed
}

func addEntryForRustCrate(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForRustCrates)
	ref = strings.Split(ref, "/")[0]

	if _, ok := indexed.EcosystemPackages[dictionary.EcosystemRustCrates]; !ok {
		indexed.EcosystemPackages[dictionary.EcosystemRustCrates] = make(dictionary.Packages)
	}

	indexed.EcosystemPackages[dictionary.EcosystemRustCrates][ref] = cpeItemName
}

func addEntryForJenkinsPlugin(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForJenkinsPlugins)
	ref = strings.Split(ref, "/")[0]

	if !strings.HasSuffix(ref, "-plugin") {
		// It's not a jenkins plugin!
		return
	}

	ref = strings.TrimSuffix(ref, "-plugin")

	if _, ok := indexed.EcosystemPackages[dictionary.EcosystemJenkinsPlugins]; !ok {
		indexed.EcosystemPackages[dictionary.EcosystemJenkinsPlugins] = make(dictionary.Packages)
	}

	indexed.EcosystemPackages[dictionary.EcosystemJenkinsPlugins][ref] = cpeItemName
}

func addEntryForPyPIPackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForPyPIPackages)
	ref = strings.Split(ref, "/")[0]

	if _, ok := indexed.EcosystemPackages[dictionary.EcosystemPyPI]; !ok {
		indexed.EcosystemPackages[dictionary.EcosystemPyPI] = make(dictionary.Packages)
	}

	indexed.EcosystemPackages[dictionary.EcosystemPyPI][ref] = cpeItemName
}

func addEntryForNativeRubyGem(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForNativeRubyGems)
	ref = strings.Split(ref, "/")[0]

	if _, ok := indexed.EcosystemPackages[dictionary.EcosystemRubyGems]; !ok {
		indexed.EcosystemPackages[dictionary.EcosystemRubyGems] = make(dictionary.Packages)
	}

	indexed.EcosystemPackages[dictionary.EcosystemRubyGems][ref] = cpeItemName
}

func addEntryForRubyGem(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.TrimPrefix(ref, prefixForRubyGems)
	ref = strings.TrimPrefix(ref, prefixForRubyGemsHTTP)
	ref = strings.Split(ref, "/")[0]

	if _, ok := indexed.EcosystemPackages[dictionary.EcosystemRubyGems]; !ok {
		indexed.EcosystemPackages[dictionary.EcosystemRubyGems] = make(dictionary.Packages)
	}

	indexed.EcosystemPackages[dictionary.EcosystemRubyGems][ref] = cpeItemName
}

func addEntryForNPMPackage(indexed *dictionary.Indexed, ref string, cpeItemName string) {
	// Prune off the non-package-name parts of the URL
	ref = strings.Split(ref, "/v/")[0]
	ref = strings.Split(ref, "?")[0]
	ref = strings.TrimPrefix(ref, prefixForNPMPackages)

	if _, ok := indexed.EcosystemPackages[dictionary.EcosystemNPM]; !ok {
		indexed.EcosystemPackages[dictionary.EcosystemNPM] = make(dictionary.Packages)
	}

	indexed.EcosystemPackages[dictionary.EcosystemNPM][ref] = cpeItemName
}
