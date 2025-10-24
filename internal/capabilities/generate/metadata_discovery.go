package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/anchore/syft/internal/capabilities/pkgtestobservation"
	"github.com/anchore/syft/internal/packagemetadata"
)

// TestObservationIndex indexes all test observations for efficient lookup and application.
// parser-level observations are indexed by package name (from test file) + parser function,
// while cataloger-level observations are indexed by cataloger name.
type TestObservationIndex struct {
	// parser-level observations: package -> parser function -> types
	parsersByPackage map[string]map[string]*TypeObservation
	// cataloger-level observations: cataloger name -> types
	catalogers map[string]*TypeObservation
}

// TypeObservation combines metadata types and package types
type TypeObservation struct {
	MetadataTypes   []string
	PackageTypes    []string
	JSONSchemaTypes []string
}

// newTestObservationIndex creates a new empty index
func newTestObservationIndex() *TestObservationIndex {
	return &TestObservationIndex{
		parsersByPackage: make(map[string]map[string]*TypeObservation),
		catalogers:       make(map[string]*TypeObservation),
	}
}

// getParserObservations retrieves parser-level observations by package name and parser function
func (idx *TestObservationIndex) getParserObservations(packageName, parserFunction string) *TypeObservation {
	if parsers, ok := idx.parsersByPackage[packageName]; ok {
		return parsers[parserFunction]
	}
	return nil
}

// getCatalogerObservations retrieves cataloger-level observations by cataloger name
func (idx *TestObservationIndex) getCatalogerObservations(catalogerName string) *TypeObservation {
	return idx.catalogers[catalogerName]
}

// setParserObservations stores parser-level observations
func (idx *TestObservationIndex) setParserObservations(packageName, parserFunction string, obs *TypeObservation) {
	if idx.parsersByPackage[packageName] == nil {
		idx.parsersByPackage[packageName] = make(map[string]*TypeObservation)
	}
	idx.parsersByPackage[packageName][parserFunction] = obs
}

// setCatalogerObservations stores cataloger-level observations
func (idx *TestObservationIndex) setCatalogerObservations(catalogerName string, obs *TypeObservation) {
	idx.catalogers[catalogerName] = obs
}

// extractCustomCatalogerData extracts cataloger-level metadata and package types for custom catalogers
func (idx *TestObservationIndex) extractCustomCatalogerData() (map[string][]string, map[string][]string) {
	metadata := make(map[string][]string)
	packageTypes := make(map[string][]string)

	for catalogerName, obs := range idx.catalogers {
		if len(obs.MetadataTypes) > 0 {
			metadata[catalogerName] = obs.MetadataTypes
		}
		if len(obs.PackageTypes) > 0 {
			packageTypes[catalogerName] = obs.PackageTypes
		}
	}

	return metadata, packageTypes
}

// findTestFixtureDirs walks the cataloger directory tree and returns all test-fixtures directories
func findTestFixtureDirs(repoRoot string) ([]string, error) {
	catalogerRoot := filepath.Join(repoRoot, "syft", "pkg", "cataloger")
	var testFixtureDirs []string

	err := filepath.Walk(catalogerRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == "test-fixtures" {
			testFixtureDirs = append(testFixtureDirs, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk cataloger directory: %w", err)
	}

	return testFixtureDirs, nil
}

// discoverMetadataTypes searches for test-observations.json files and merges metadata type information
// into the discovered catalogers. Returns maps of custom cataloger metadata types and package types.
func discoverMetadataTypes(repoRoot string, discovered map[string]DiscoveredCataloger) (map[string][]string, map[string][]string, error) {
	testFixtureDirs, err := findTestFixtureDirs(repoRoot)
	if err != nil {
		return nil, nil, err
	}

	// create index to aggregate all observations
	index := newTestObservationIndex()

	// read all test-observations files and merge into index
	for _, dir := range testFixtureDirs {
		observationsFile := filepath.Join(dir, "test-observations.json")
		if observations, err := readTestObservations(observationsFile); err == nil {
			mergeTestObservations(observations, index)
		} else if !os.IsNotExist(err) {
			fmt.Printf("  Warning: failed to read %s: %v\n", observationsFile, err)
		}
	}

	// check if any observations were found
	if len(index.parsersByPackage) == 0 && len(index.catalogers) == 0 {
		// no metadata found, this is not an error
		return nil, nil, nil
	}

	// apply observations to discovered catalogers
	applyTypesToCatalogers(discovered, index)

	// extract custom cataloger data for return
	customMetadata, customPackageTypes := index.extractCustomCatalogerData()
	return customMetadata, customPackageTypes, nil
}

// readTestObservations reads and parses a test-observations.json file
func readTestObservations(path string) (*pkgtestobservation.Test, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var observations pkgtestobservation.Test
	if err := json.Unmarshal(data, &observations); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &observations, nil
}

// mergeAndDeduplicateStrings merges two string slices, removes duplicates, and returns a sorted slice
func mergeAndDeduplicateStrings(existing, additional []string) []string {
	set := make(map[string]bool)
	for _, s := range existing {
		set[s] = true
	}
	for _, s := range additional {
		set[s] = true
	}

	result := make([]string, 0, len(set))
	for s := range set {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

// convertToJSONSchemaTypes converts Go struct names to UpperCamelCase JSON schema names
func convertToJSONSchemaTypes(metadataTypes []string) []string {
	if len(metadataTypes) == 0 {
		return nil
	}

	result := make([]string, 0, len(metadataTypes))
	for _, typeName := range metadataTypes {
		jsonName := packagemetadata.JSONNameFromString(typeName)
		if jsonName != "" {
			camelCase := packagemetadata.ToUpperCamelCase(jsonName)
			result = append(result, camelCase)
		}
	}
	return result
}

// mergeTestObservations merges metadata and package type data from a test-observations.json file
// into the observation index
func mergeTestObservations(observations *pkgtestobservation.Test, index *TestObservationIndex) {
	pkg := observations.Package

	// merge parser-level observations
	for parserName, parserObs := range observations.Parsers {
		if len(parserObs.MetadataTypes) == 0 && len(parserObs.PackageTypes) == 0 {
			continue
		}

		existing := index.getParserObservations(pkg, parserName)
		if existing == nil {
			existing = &TypeObservation{}
		}

		// merge the types
		existing.MetadataTypes = mergeAndDeduplicateStrings(existing.MetadataTypes, parserObs.MetadataTypes)
		existing.PackageTypes = mergeAndDeduplicateStrings(existing.PackageTypes, parserObs.PackageTypes)
		// generate JSON schema types from metadata types
		existing.JSONSchemaTypes = convertToJSONSchemaTypes(existing.MetadataTypes)

		index.setParserObservations(pkg, parserName, existing)
	}

	// merge cataloger-level observations
	for catalogerName, catalogerObs := range observations.Catalogers {
		if len(catalogerObs.MetadataTypes) == 0 && len(catalogerObs.PackageTypes) == 0 {
			continue
		}

		existing := index.getCatalogerObservations(catalogerName)
		if existing == nil {
			existing = &TypeObservation{}
		}

		// merge the types
		existing.MetadataTypes = mergeAndDeduplicateStrings(existing.MetadataTypes, catalogerObs.MetadataTypes)
		existing.PackageTypes = mergeAndDeduplicateStrings(existing.PackageTypes, catalogerObs.PackageTypes)
		// generate JSON schema types from metadata types
		existing.JSONSchemaTypes = convertToJSONSchemaTypes(existing.MetadataTypes)

		index.setCatalogerObservations(catalogerName, existing)
	}
}

// applyParserObservations applies parser-level observations to a cataloger's parsers
func applyParserObservations(cataloger *DiscoveredCataloger, index *TestObservationIndex) bool {
	foundData := false

	// apply parser-level observations by matching package name + parser function
	for i, parser := range cataloger.Parsers {
		if obs := index.getParserObservations(cataloger.PackageName, parser.ParserFunction); obs != nil {
			if len(obs.MetadataTypes) > 0 {
				cataloger.Parsers[i].MetadataTypes = obs.MetadataTypes
				cataloger.Parsers[i].JSONSchemaTypes = obs.JSONSchemaTypes
				foundData = true
			}
			if len(obs.PackageTypes) > 0 {
				cataloger.Parsers[i].PackageTypes = obs.PackageTypes
				foundData = true
			}
		}
	}

	return foundData
}

// applySingleParserCatalogerObservations applies cataloger-level observations to a single-parser cataloger
// by merging them with any existing parser-level observations
func applySingleParserCatalogerObservations(cataloger *DiscoveredCataloger, catalogerObs *TypeObservation) bool {
	foundData := false

	if len(catalogerObs.MetadataTypes) > 0 {
		cataloger.Parsers[0].MetadataTypes = mergeAndDeduplicateStrings(
			cataloger.Parsers[0].MetadataTypes,
			catalogerObs.MetadataTypes,
		)
		cataloger.Parsers[0].JSONSchemaTypes = convertToJSONSchemaTypes(cataloger.Parsers[0].MetadataTypes)
		foundData = true
	}

	if len(catalogerObs.PackageTypes) > 0 {
		cataloger.Parsers[0].PackageTypes = mergeAndDeduplicateStrings(
			cataloger.Parsers[0].PackageTypes,
			catalogerObs.PackageTypes,
		)
		foundData = true
	}

	return foundData
}

// applyMultiParserCatalogerObservations applies cataloger-level observations to a multi-parser cataloger
// only applies to parsers that don't already have parser-level data
func applyMultiParserCatalogerObservations(cataloger *DiscoveredCataloger, catalogerObs *TypeObservation) bool {
	foundData := false

	// count parsers without any data
	parsersWithoutData := 0
	for _, parser := range cataloger.Parsers {
		if len(parser.MetadataTypes) == 0 && len(parser.PackageTypes) == 0 {
			parsersWithoutData++
		}
	}

	// if all parsers lack data, apply to all and warn
	if parsersWithoutData == len(cataloger.Parsers) {
		fmt.Printf("  Warning: cataloger %q has %d parsers but only cataloger-level observations. Consider adding parser-level tests for better granularity.\n",
			cataloger.Name, len(cataloger.Parsers))

		for i := range cataloger.Parsers {
			if len(catalogerObs.MetadataTypes) > 0 {
				cataloger.Parsers[i].MetadataTypes = catalogerObs.MetadataTypes
				cataloger.Parsers[i].JSONSchemaTypes = catalogerObs.JSONSchemaTypes
				foundData = true
			}
			if len(catalogerObs.PackageTypes) > 0 {
				cataloger.Parsers[i].PackageTypes = catalogerObs.PackageTypes
				foundData = true
			}
		}
	} else if parsersWithoutData > 0 {
		// only apply to parsers without data
		for i, parser := range cataloger.Parsers {
			if len(parser.MetadataTypes) == 0 && len(catalogerObs.MetadataTypes) > 0 {
				cataloger.Parsers[i].MetadataTypes = catalogerObs.MetadataTypes
				cataloger.Parsers[i].JSONSchemaTypes = catalogerObs.JSONSchemaTypes
				foundData = true
			}
			if len(parser.PackageTypes) == 0 && len(catalogerObs.PackageTypes) > 0 {
				cataloger.Parsers[i].PackageTypes = catalogerObs.PackageTypes
				foundData = true
			}
		}
	}

	return foundData
}

// applyTypesToCatalogers applies the aggregated metadata and package type data to the discovered catalogers.
// it updates the cataloger's parser entries with the appropriate metadata and package types.
func applyTypesToCatalogers(discovered map[string]DiscoveredCataloger, index *TestObservationIndex) {
	for catalogerName, cataloger := range discovered {
		var foundData bool

		// first, apply parser-level observations
		if applyParserObservations(&cataloger, index) {
			foundData = true
		}

		// then, apply cataloger-level observations if they exist
		if catalogerObs := index.getCatalogerObservations(catalogerName); catalogerObs != nil && len(cataloger.Parsers) > 0 {
			if len(cataloger.Parsers) == 1 {
				// single parser: merge cataloger-level with parser-level observations
				if applySingleParserCatalogerObservations(&cataloger, catalogerObs) {
					foundData = true
				}
			} else {
				// multiple parsers: only apply to parsers without parser-level data
				if applyMultiParserCatalogerObservations(&cataloger, catalogerObs) {
					foundData = true
				}
			}
		}

		if foundData {
			discovered[catalogerName] = cataloger
		}
	}
}
