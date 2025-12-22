// this file contains the core merging logic that combines discovered cataloger data with existing cataloger/*/capabilities.yaml files, preserving all manual sections while updating auto-generated fields.
package main

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/capabilities/internal"
	"github.com/anchore/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
)

const genericCatalogerType = "generic"

// stripPURLVersion removes the @version suffix from a PURL string
// e.g., "pkg:generic/python@version" -> "pkg:generic/python"
func stripPURLVersion(purl string) string {
	if idx := strings.LastIndex(purl, "@"); idx != -1 {
		return purl[:idx]
	}
	return purl
}

// catalogerTypeOverrides specifies catalogers that should have their type manually controlled
// rather than determined from the discovered cataloger structure.
// This is useful when a cataloger is discovered as "generic" but should be treated as "custom"
// in the YAML (or vice versa).
var catalogerTypeOverrides = map[string]string{
	// the java cataloger is technically generic (it has parsers), but we want it to be treated as custom since
	// these nuances can't automatically be detected, and it requires manual source info
	"java-archive-cataloger": "custom",
}

// catalogerConfigExceptions specifies catalogers that should NOT have config fields
// auto-generated even if a config mapping is discovered via AST parsing.
// This is useful when a cataloger uses a config struct internally but it shouldn't
// be exposed in the capabilities document.
var catalogerConfigExceptions = strset.New(
	"binary-classifier-cataloger",
)

// catalogerConfigOverrides specifies manual mappings from cataloger names to config struct names.
// Use this when the AST parser cannot automatically discover the config linkage, or when you want
// to explicitly override the discovered mapping.
// Format: cataloger-name -> "package.ConfigStructName"
var catalogerConfigOverrides = map[string]string{
	"dotnet-portable-executable-cataloger": "dotnet.CatalogerConfig",
	"nix-store-cataloger":                  "nix.Config",
}

// ecosystemMapping maps patterns in cataloger names to ecosystem names.
// order matters - more specific patterns should come first.
type ecosystemMapping struct {
	patterns  []string // patterns to match in the cataloger name
	ecosystem string   // ecosystem to return if any pattern matches
}

// ecosystemMappings defines the pattern-to-ecosystem mappings.
// note: order matters - check more specific patterns first
var ecosystemMappings = []ecosystemMapping{
	// language-based ecosystems
	{[]string{"rust", "cargo"}, "rust"},
	{[]string{"javascript", "node", "npm"}, "javascript"},
	{[]string{"python"}, "python"},
	{[]string{"java", "graalvm"}, "java"},
	{[]string{"go-module", "golang"}, "go"},
	{[]string{"ruby", "gem"}, "ruby"},
	{[]string{"php", "composer", "pear", "pecl"}, "php"},
	{[]string{"dotnet", ".net", "csharp"}, "dotnet"},
	{[]string{"swift", "cocoapods"}, "swift"},
	{[]string{"dart", "pubspec"}, "dart"},
	{[]string{"elixir", "mix"}, "elixir"},
	{[]string{"erlang", "rebar"}, "erlang"},
	{[]string{"haskell", "cabal", "stack"}, "haskell"},
	{[]string{"lua"}, "lua"},
	{[]string{"ocaml", "opam"}, "ocaml"},
	{[]string{"r-package"}, "r"},
	{[]string{"swipl", "prolog"}, "prolog"},
	{[]string{"cpp", "conan"}, "c++"},
	{[]string{"kotlin"}, "kotlin"},

	// os/distro-based ecosystems
	{[]string{"apk", "alpine"}, "alpine"},
	{[]string{"dpkg", "deb", "debian"}, "debian"},
	{[]string{"rpm", "redhat"}, "rpm"},
	{[]string{"alpm", "arch"}, "arch"},
	{[]string{"portage", "gentoo"}, "gentoo"},
	{[]string{"homebrew"}, "homebrew"},
	{[]string{"snap"}, "snap"},

	// other ecosystems
	{[]string{"binary", "elf", "pe-binary"}, "binary"},
	{[]string{"conda"}, "conda"},
	{[]string{"nix"}, "nix"},
	{[]string{"kernel"}, "kernel"},
	{[]string{"bitnami"}, "bitnami"},
	{[]string{"terraform"}, "terraform"},
	{[]string{"github"}, "github-actions"},
	{[]string{"wordpress"}, "wordpress"},
	{[]string{"sbom"}, "sbom"},
}

// inferEcosystem attempts to determine the ecosystem from a cataloger name
func inferEcosystem(catalogerName string) string {
	name := strings.ToLower(catalogerName)

	for _, mapping := range ecosystemMappings {
		for _, pattern := range mapping.patterns {
			if strings.Contains(name, pattern) {
				return mapping.ecosystem
			}
		}
	}

	// default
	return "other"
}

// Statistics contains information about the regeneration process
type Statistics struct {
	TotalGenericCatalogers int
	TotalCustomCatalogers  int
	TotalParserFunctions   int
	NewCatalogers          []string
	NewParserFunctions     []string
	UpdatedCatalogers      []string
}

// RegenerateCapabilities updates the distributed YAML files with discovered catalogers
// while preserving manually-edited capability information.
// This is exported for use by the generator in generate/main.go
func RegenerateCapabilities(catalogerDir string, repoRoot string) (*Statistics, error) {
	stats := &Statistics{}

	// 1-2. Discover all cataloger data
	discovered, customCatalogerMetadata, customCatalogerPackageTypes, binaryClassifiers, allCatalogers, err := discoverAllCatalogerData(repoRoot, stats)
	if err != nil {
		return nil, err
	}

	// 3. Load existing YAML files - now returns both document and node trees
	fmt.Print("  → Loading existing capabilities files...")
	existing, existingNodes, err := internal.LoadCapabilities(catalogerDir, repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to load existing capabilities: %w", err)
	}
	fmt.Printf(" loaded %d entries\n", len(existing.Catalogers))

	// 3a-3c. Discover and process all config-related information
	discoveredConfigs, err := discoverAndFilterConfigs(repoRoot)
	if err != nil {
		return nil, err
	}

	discoveredAppConfigs, err := discoverAndConvertAppConfigs(repoRoot)
	if err != nil {
		return nil, err
	}

	catalogerConfigMappings, err := LinkCatalogersToConfigs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to link catalogers to configs: %w", err)
	}
	fmt.Printf("  → Linking catalogers to config structs... found %d mappings\n", len(catalogerConfigMappings))

	filteredCatalogerConfigMappings := applyConfigMappingFilters(catalogerConfigMappings)

	// 4. Build updated catalogers list
	fmt.Println("  → Merging discovered catalogers with existing entries...")
	updated, orphans, mergeStats := mergeDiscoveredWithExisting(
		discovered,
		customCatalogerMetadata,
		customCatalogerPackageTypes,
		binaryClassifiers,
		allCatalogers,
		existing,
		discoveredConfigs,
		discoveredAppConfigs,
		filteredCatalogerConfigMappings,
	)
	stats.NewCatalogers = mergeStats.NewCatalogers
	stats.NewParserFunctions = mergeStats.NewParserFunctions
	stats.UpdatedCatalogers = mergeStats.UpdatedCatalogers
	stats.TotalCustomCatalogers = len(allCatalogers) - stats.TotalGenericCatalogers

	// 5. Check for orphaned parsers (parser functions that were renamed/deleted)
	if len(orphans) > 0 {
		return nil, fmt.Errorf("orphaned parsers detected (parser functions renamed or deleted):\n%s\n\nPlease manually remove these from the capabilities files or restore the parser functions in the code",
			formatOrphans(orphans))
	}

	// 6. Write back to YAML files with comments, preserving existing node trees
	fmt.Print("  → Writing updated capabilities files...")
	if err := saveCapabilities(catalogerDir, repoRoot, updated, existingNodes); err != nil {
		return nil, fmt.Errorf("failed to save capabilities: %w", err)
	}
	fmt.Println(" done")

	return stats, nil
}

// discoverAllCatalogerData discovers all cataloger-related data including generic catalogers, metadata, binary classifiers, and all catalogers
func discoverAllCatalogerData(repoRoot string, stats *Statistics) (
	map[string]DiscoveredCataloger,
	map[string][]string,
	map[string][]string,
	[]binary.Classifier, //nolint:staticcheck
	[]capabilities.CatalogerInfo,
	error,
) {
	// discover generic catalogers
	fmt.Print("  → Scanning source code for generic catalogers...")
	discovered, err := discoverGenericCatalogers(repoRoot)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to discover catalogers: %w", err)
	}
	stats.TotalGenericCatalogers = len(discovered)
	fmt.Printf(" found %d\n", stats.TotalGenericCatalogers)

	// discover metadata types
	fmt.Print("  → Searching for metadata type and package type information...")
	customCatalogerMetadata, customCatalogerPackageTypes, err := discoverMetadataTypes(repoRoot, discovered)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to discover metadata types: %w", err)
	}
	fmt.Println(" done")

	// extract binary classifiers
	fmt.Print("  → Extracting binary classifiers...")
	binaryClassifiers := extractBinaryClassifiers()
	fmt.Printf(" found %d classifiers\n", len(binaryClassifiers))

	// count parser functions
	for _, disc := range discovered {
		stats.TotalParserFunctions += len(disc.Parsers)
	}

	// get all cataloger info
	fmt.Print("  → Fetching all cataloger info from syft...")
	allCatalogers, err := internal.AllPackageCatalogerInfo()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to get cataloger info: %w", err)
	}
	fmt.Printf(" found %d total\n", len(allCatalogers))

	return discovered, customCatalogerMetadata, customCatalogerPackageTypes, binaryClassifiers, allCatalogers, nil
}

// discoverAndFilterConfigs discovers cataloger config structs, filters by whitelist, and converts to capabilities format
func discoverAndFilterConfigs(repoRoot string) (map[string]capabilities.CatalogerConfigEntry, error) {
	fmt.Print("  → Discovering cataloger config structs...")
	configInfoMap, err := DiscoverConfigs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to discover configs: %w", err)
	}
	fmt.Printf(" found %d\n", len(configInfoMap))

	fmt.Print("  → Filtering configs by pkgcataloging.Config whitelist...")
	allowedConfigs, err := DiscoverAllowedConfigStructs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to discover allowed config structs: %w", err)
	}

	// filter discovered configs to only include allowed ones
	filteredConfigInfoMap := make(map[string]ConfigInfo)
	for key, configInfo := range configInfoMap {
		if allowedConfigs[key] {
			filteredConfigInfoMap[key] = configInfo
		}
	}
	fmt.Printf(" %d allowed (filtered %d)\n", len(filteredConfigInfoMap), len(configInfoMap)-len(filteredConfigInfoMap))

	// convert ConfigInfo to CatalogerConfigEntry format for ecosystem YAML files
	discoveredConfigs := make(map[string]capabilities.CatalogerConfigEntry)
	for key, configInfo := range filteredConfigInfoMap {
		fields := make([]capabilities.CatalogerConfigFieldEntry, len(configInfo.Fields))
		for i, field := range configInfo.Fields {
			fields[i] = capabilities.CatalogerConfigFieldEntry{
				Key:         field.Name,
				Description: field.Description,
				AppKey:      field.AppKey,
			}
		}
		discoveredConfigs[key] = capabilities.CatalogerConfigEntry{
			Fields: fields,
		}
	}

	return discoveredConfigs, nil
}

// discoverAndConvertAppConfigs discovers app-level config fields and converts them to capabilities format
func discoverAndConvertAppConfigs(repoRoot string) ([]capabilities.ApplicationConfigField, error) {
	fmt.Print("  → Discovering app-level config fields...")
	appConfigFields, err := DiscoverAppConfigs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to discover app configs: %w", err)
	}
	fmt.Printf(" found %d\n", len(appConfigFields))

	// convert to ApplicationConfigField format
	discoveredAppConfigs := make([]capabilities.ApplicationConfigField, len(appConfigFields))
	for i, field := range appConfigFields {
		discoveredAppConfigs[i] = capabilities.ApplicationConfigField{
			Key:          field.Key,
			Description:  field.Description,
			DefaultValue: field.DefaultValue,
		}
	}

	return discoveredAppConfigs, nil
}

// applyConfigMappingFilters applies exceptions and manual overrides to cataloger config mappings
func applyConfigMappingFilters(catalogerConfigMappings map[string]string) map[string]string {
	// filter by exceptions
	fmt.Print("  → Filtering cataloger config mappings by exceptions...")
	filteredCatalogerConfigMappings := make(map[string]string)
	filteredCount := 0
	for catalogerName, configName := range catalogerConfigMappings {
		if catalogerConfigExceptions.Has(catalogerName) {
			filteredCount++
			continue
		}
		filteredCatalogerConfigMappings[catalogerName] = configName
	}
	if filteredCount > 0 {
		fmt.Printf(" filtered %d\n", filteredCount)
	} else {
		fmt.Println(" none")
	}

	// merge manual overrides
	fmt.Print("  → Merging manual config overrides...")
	overrideCount := 0
	for catalogerName, configName := range catalogerConfigOverrides {
		if catalogerConfigExceptions.Has(catalogerName) {
			continue
		}
		filteredCatalogerConfigMappings[catalogerName] = configName
		overrideCount++
	}
	if overrideCount > 0 {
		fmt.Printf(" added %d\n", overrideCount)
	} else {
		fmt.Println(" none")
	}

	return filteredCatalogerConfigMappings
}

type orphanInfo struct {
	catalogerName  string
	parserFunction string
}

type mergeStatistics struct {
	NewCatalogers      []string
	NewParserFunctions []string
	UpdatedCatalogers  []string
}

// CatalogerRegistry encapsulates cataloger lookup data and provides methods for querying cataloger information
type CatalogerRegistry struct {
	discovered map[string]DiscoveredCataloger
	all        []capabilities.CatalogerInfo
	infoByName map[string]*capabilities.CatalogerInfo
}

// NewCatalogerRegistry creates a new registry with the given discovered and all catalogers
func NewCatalogerRegistry(discovered map[string]DiscoveredCataloger, all []capabilities.CatalogerInfo) *CatalogerRegistry {
	infoByName := make(map[string]*capabilities.CatalogerInfo)
	for i := range all {
		infoByName[all[i].Name] = &all[i]
	}

	return &CatalogerRegistry{
		discovered: discovered,
		all:        all,
		infoByName: infoByName,
	}
}

// IsGeneric checks if a cataloger is a discovered generic cataloger and returns it if found
func (r *CatalogerRegistry) IsGeneric(name string) (DiscoveredCataloger, bool) {
	disc, ok := r.discovered[name]
	return disc, ok
}

// GetInfo returns the cataloger info for the given name, or nil if not found
func (r *CatalogerRegistry) GetInfo(name string) *capabilities.CatalogerInfo {
	return r.infoByName[name]
}

// DiscoveredCatalogers returns all discovered generic catalogers
func (r *CatalogerRegistry) DiscoveredCatalogers() map[string]DiscoveredCataloger {
	return r.discovered
}

// AllCatalogers returns all catalogers from the syft cataloger list
func (r *CatalogerRegistry) AllCatalogers() []capabilities.CatalogerInfo {
	return r.all
}

// EnrichmentData encapsulates metadata enrichment information (metadata types, package types, binary classifiers)
type EnrichmentData struct {
	metadata          map[string][]string
	packageTypes      map[string][]string
	binaryClassifiers []binary.Classifier //nolint:staticcheck
}

// NewEnrichmentData creates a new enrichment data container
func NewEnrichmentData(metadata, packageTypes map[string][]string, binaryClassifiers []binary.Classifier) *EnrichmentData { //nolint:staticcheck
	return &EnrichmentData{
		metadata:          metadata,
		packageTypes:      packageTypes,
		binaryClassifiers: binaryClassifiers,
	}
}

// GetMetadataTypes returns the metadata types for the given cataloger name
func (e *EnrichmentData) GetMetadataTypes(catalogerName string) ([]string, bool) {
	types, ok := e.metadata[catalogerName]
	return types, ok
}

// GetPackageTypes returns the package types for the given cataloger name
func (e *EnrichmentData) GetPackageTypes(catalogerName string) ([]string, bool) {
	types, ok := e.packageTypes[catalogerName]
	return types, ok
}

// EnrichEntry enriches a cataloger entry with metadata types and package types if available
func (e *EnrichmentData) EnrichEntry(catalogerName string, entry *capabilities.CatalogerEntry) {
	// update metadata types if available
	if types, ok := e.GetMetadataTypes(catalogerName); ok {
		entry.MetadataTypes = types
		// generate JSON schema types from metadata types
		entry.JSONSchemaTypes = convertToJSONSchemaTypesFromMetadata(types)
	}
	// update package types if available
	if types, ok := e.GetPackageTypes(catalogerName); ok {
		entry.PackageTypes = types
	}
}

// convertToJSONSchemaTypesFromMetadata converts Go struct names to UpperCamelCase JSON schema names
func convertToJSONSchemaTypesFromMetadata(metadataTypes []string) []string {
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

// EnrichWithBinaryClassifier enriches an entry with binary classifier detectors if it's the binary-classifier-cataloger
func (e *EnrichmentData) EnrichWithBinaryClassifier(catalogerName string, entry *capabilities.CatalogerEntry) {
	// special handling for binary-classifier-cataloger: auto-generate one detector per classifier
	if catalogerName == "binary-classifier-cataloger" && len(e.binaryClassifiers) > 0 {
		var detectors []capabilities.Detector
		for _, classifier := range e.binaryClassifiers {
			// convert CPEs to strings
			cpeStrings := make([]string, len(classifier.CPEs))
			for i, c := range classifier.CPEs {
				cpeStrings[i] = c.Attributes.BindToFmtString()
			}

			// strip @version from PURL
			purlStr := stripPURLVersion(classifier.PURL.String())

			packages := []capabilities.DetectorPackageInfo{
				{
					Class: classifier.Class,
					Name:  classifier.Package,
					PURL:  purlStr,
					CPEs:  cpeStrings,
					Type:  "BinaryPkg",
				},
			}

			for _, o := range binaryClassifierOverrides[classifier.Class] {
				packages = append(packages, capabilities.DetectorPackageInfo{
					Class: o.Class,
					Name:  o.Package,
					PURL:  stripPURLVersion(o.PURL),
					CPEs:  o.CPEs,
					Type:  "BinaryPkg",
				})
			}

			detectors = append(detectors, capabilities.Detector{
				Method:   "glob",
				Criteria: []string{classifier.FileGlob},
				Packages: packages,
			})
		}
		entry.Detectors = detectors
	}
}

// CatalogerMerger orchestrates the merging of discovered catalogers with existing capabilities
type CatalogerMerger struct {
	registry                *CatalogerRegistry
	enrichment              *EnrichmentData
	existing                *capabilities.Document
	catalogerConfigMappings map[string]string // catalogerName -> config struct name

	// internal merge state
	updated             *capabilities.Document
	processedCatalogers map[string]bool
	orphans             []orphanInfo
	stats               *mergeStatistics
}

// NewCatalogerMerger creates a new merger with the given registry, enrichment data, and existing document
func NewCatalogerMerger(registry *CatalogerRegistry, enrichment *EnrichmentData, existing *capabilities.Document, catalogerConfigMappings map[string]string) *CatalogerMerger {
	return &CatalogerMerger{
		registry:                registry,
		enrichment:              enrichment,
		existing:                existing,
		catalogerConfigMappings: catalogerConfigMappings,
		updated:                 &capabilities.Document{},
		processedCatalogers:     make(map[string]bool),
		stats:                   &mergeStatistics{},
	}
}

// Merge performs the merge operation and returns the updated document, orphans, and statistics.
// Note: Configs and ApplicationConfig must be set on the merger's updated document before or after calling Merge.
// They are AUTO-GENERATED sections that are completely replaced during regeneration.
func (m *CatalogerMerger) Merge() (*capabilities.Document, []orphanInfo, *mergeStatistics) {
	// process catalogers
	m.processExistingCatalogers()
	m.addNewGenericCatalogers()
	m.addNewCustomCatalogers()
	return m.updated, m.orphans, m.stats
}

// processExistingCatalogers processes all existing catalogers in their original order
func (m *CatalogerMerger) processExistingCatalogers() {
	for i := range m.existing.Catalogers {
		existingEntry := &m.existing.Catalogers[i]
		catalogerName := existingEntry.Name

		disc, isGeneric := m.registry.IsGeneric(catalogerName)
		info := m.registry.GetInfo(catalogerName)

		switch {
		case isGeneric:
			// existing generic cataloger - update auto-gen fields, preserve manual, check for orphans
			m.processGenericCataloger(existingEntry, disc, info)

		case info != nil:
			// existing custom cataloger - preserve but update ecosystem, selectors, metadata types, and package types
			m.processCustomCataloger(existingEntry, info)

		default:
			// cataloger no longer exists in syft - keep it as-is (user may have added manually)
			m.updated.Catalogers = append(m.updated.Catalogers, *existingEntry)
		}

		m.processedCatalogers[catalogerName] = true
	}
}

// addNewGenericCatalogers appends any new generic catalogers that weren't in existing
func (m *CatalogerMerger) addNewGenericCatalogers() {
	for catalogerName, disc := range m.registry.DiscoveredCatalogers() {
		if m.processedCatalogers[catalogerName] {
			continue
		}

		info := m.registry.GetInfo(catalogerName)
		// new generic cataloger - create with template
		entry := createTemplateEntry(disc, info)
		// update config field from discovered mappings
		if configName, hasConfig := m.catalogerConfigMappings[catalogerName]; hasConfig {
			entry.Config = configName
		}
		m.updated.Catalogers = append(m.updated.Catalogers, entry)
		m.stats.NewCatalogers = append(m.stats.NewCatalogers, catalogerName)
		for _, parser := range disc.Parsers {
			m.stats.NewParserFunctions = append(m.stats.NewParserFunctions, fmt.Sprintf("%s/%s", catalogerName, parser.ParserFunction))
		}

		m.processedCatalogers[catalogerName] = true
	}
}

// addNewCustomCatalogers appends any new custom catalogers from syft cataloger list
func (m *CatalogerMerger) addNewCustomCatalogers() {
	for _, catalogerInfo := range m.registry.AllCatalogers() {
		catalogerName := catalogerInfo.Name
		if m.processedCatalogers[catalogerName] {
			continue
		}

		// new custom cataloger - create template entry
		entry := capabilities.CatalogerEntry{
			Ecosystem: inferEcosystem(catalogerName),
			Name:      catalogerName,
			Type:      "custom",
			Source: capabilities.Source{
				File:     "", // must be filled manually
				Function: "", // must be filled manually
			},
			Selectors:    catalogerInfo.Selectors,
			Capabilities: capabilities.CapabilitySet{}, // empty array - must be filled manually
		}

		// update config field from discovered mappings
		if configName, hasConfig := m.catalogerConfigMappings[catalogerName]; hasConfig {
			entry.Config = configName
		}

		// enrich with metadata and package types
		m.enrichment.EnrichEntry(catalogerName, &entry)

		// fallback: if we have metadata_types but no json_schema_types, convert them
		// this handles cases where metadata_types exist in YAML but no enrichment data
		if len(entry.MetadataTypes) > 0 && len(entry.JSONSchemaTypes) == 0 {
			entry.JSONSchemaTypes = convertToJSONSchemaTypesFromMetadata(entry.MetadataTypes)
		}

		// enrich with binary classifier globs
		m.enrichment.EnrichWithBinaryClassifier(catalogerName, &entry)

		m.updated.Catalogers = append(m.updated.Catalogers, entry)
		m.stats.NewCatalogers = append(m.stats.NewCatalogers, catalogerName)

		m.processedCatalogers[catalogerName] = true
	}
}

// processGenericCataloger processes an existing generic cataloger entry
func (m *CatalogerMerger) processGenericCataloger(existingEntry *capabilities.CatalogerEntry, disc DiscoveredCataloger, info *capabilities.CatalogerInfo) {
	entry, catalogerOrphans, newParsers := updateEntry(existingEntry, disc, info, m.catalogerConfigMappings)

	// fallback for catalogers with type override to custom but processed as generic
	// these may have cataloger-level metadata_types that need json_schema_types
	if len(entry.MetadataTypes) > 0 && len(entry.JSONSchemaTypes) == 0 {
		entry.JSONSchemaTypes = convertToJSONSchemaTypesFromMetadata(entry.MetadataTypes)
	}

	m.updated.Catalogers = append(m.updated.Catalogers, entry)
	m.orphans = append(m.orphans, catalogerOrphans...)
	if len(newParsers) > 0 || len(catalogerOrphans) > 0 {
		m.stats.UpdatedCatalogers = append(m.stats.UpdatedCatalogers, existingEntry.Name)
	}
	for _, parser := range newParsers {
		m.stats.NewParserFunctions = append(m.stats.NewParserFunctions, fmt.Sprintf("%s/%s", existingEntry.Name, parser))
	}
}

// processCustomCataloger processes an existing custom cataloger entry
func (m *CatalogerMerger) processCustomCataloger(existingEntry *capabilities.CatalogerEntry, info *capabilities.CatalogerInfo) {
	entry := *existingEntry
	// only infer ecosystem if not manually set (ecosystem is MANUAL)
	if existingEntry.Ecosystem == "" {
		entry.Ecosystem = inferEcosystem(existingEntry.Name)
	}
	entry.Selectors = info.Selectors

	// update config field from discovered mappings (AUTO-GENERATED)
	if configName, hasConfig := m.catalogerConfigMappings[existingEntry.Name]; hasConfig {
		entry.Config = configName
	}

	// enrich with metadata and package types
	m.enrichment.EnrichEntry(existingEntry.Name, &entry)

	// fallback: if we have metadata_types but no json_schema_types, convert them
	// this handles cases where metadata_types exist in YAML but no enrichment data
	if len(entry.MetadataTypes) > 0 && len(entry.JSONSchemaTypes) == 0 {
		entry.JSONSchemaTypes = convertToJSONSchemaTypesFromMetadata(entry.MetadataTypes)
	}

	// enrich with binary classifier globs
	m.enrichment.EnrichWithBinaryClassifier(existingEntry.Name, &entry)

	m.updated.Catalogers = append(m.updated.Catalogers, entry)
}

// mergeDiscoveredWithExisting combines discovered cataloger information with existing capabilities,
// preserving manual sections (capabilities) while updating AUTO-GENERATED sections.
//
// The configs and appConfigs parameters are AUTO-GENERATED sections that completely replace
// any existing configs/app-config data in the ecosystem YAML files.
//
// The catalogerConfigMappings parameter maps cataloger names to their config struct names
// (e.g., "go-module-binary-cataloger" -> "golang.CatalogerConfig").
func mergeDiscoveredWithExisting(
	discovered map[string]DiscoveredCataloger,
	customMetadata map[string][]string,
	customPackageTypes map[string][]string,
	binaryClassifiers []binary.Classifier, //nolint:staticcheck
	allCatalogers []capabilities.CatalogerInfo,
	existing *capabilities.Document,
	configs map[string]capabilities.CatalogerConfigEntry,
	appConfigs []capabilities.ApplicationConfigField,
	catalogerConfigMappings map[string]string,
) (*capabilities.Document, []orphanInfo, *mergeStatistics) {
	registry := NewCatalogerRegistry(discovered, allCatalogers)
	enrichment := NewEnrichmentData(customMetadata, customPackageTypes, binaryClassifiers)
	merger := NewCatalogerMerger(registry, enrichment, existing, catalogerConfigMappings)

	// set the AUTO-GENERATED config sections
	// these completely replace any existing data (not merged)
	merger.updated.Configs = configs
	merger.updated.ApplicationConfig = appConfigs

	return merger.Merge()
}

func updateEntry(existing *capabilities.CatalogerEntry, discovered DiscoveredCataloger, info *capabilities.CatalogerInfo, catalogerConfigMappings map[string]string) (capabilities.CatalogerEntry, []orphanInfo, []string) {
	updated := *existing

	// update AUTO-GENERATED fields
	updated.Name = discovered.Name

	// check if there's a type override for this cataloger
	if overrideType, hasOverride := catalogerTypeOverrides[discovered.Name]; hasOverride {
		updated.Type = overrideType
	} else {
		updated.Type = discovered.Type
	}

	updated.Source = capabilities.Source{
		File:     discovered.SourceFile,
		Function: discovered.SourceFunction,
	}

	// update selectors from cataloger info
	if info != nil {
		updated.Selectors = info.Selectors
	}

	// update config field from discovered mappings (AUTO-GENERATED)
	if configName, hasConfig := catalogerConfigMappings[discovered.Name]; hasConfig {
		updated.Config = configName
	} else {
		// clear config if no mapping exists (it may have been removed)
		updated.Config = ""
	}

	// only infer ecosystem if not manually set (ecosystem is MANUAL)
	if existing.Ecosystem == "" {
		updated.Ecosystem = inferEcosystem(discovered.Name)
	}

	var orphans []orphanInfo
	var newParsers []string

	// update parsers only if the final type is generic (not overridden to custom)
	// if a cataloger is overridden from generic to custom, we don't update parsers
	if discovered.Type == genericCatalogerType && updated.Type == genericCatalogerType {
		updatedParsers, parserOrphans, newParserFuncs := updateParsers(existing.Parsers, discovered.Parsers, discovered.Name)
		updated.Parsers = updatedParsers
		orphans = append(orphans, parserOrphans...)
		newParsers = newParserFuncs
	}

	return updated, orphans, newParsers
}

func updateParsers(existingParsers []capabilities.Parser, discoveredParsers []DiscoveredParser, catalogerName string) ([]capabilities.Parser, []orphanInfo, []string) {
	var updated []capabilities.Parser
	var orphans []orphanInfo
	var newParserFuncs []string

	// create lookup for discovered parsers by parser function
	discoveredByParserFunc := make(map[string]*DiscoveredParser)
	for i := range discoveredParsers {
		discoveredByParserFunc[discoveredParsers[i].ParserFunction] = &discoveredParsers[i]
	}

	// create lookup for existing parsers by parser function
	existingByParserFunc := make(map[string]*capabilities.Parser)
	for i := range existingParsers {
		existingByParserFunc[existingParsers[i].ParserFunction] = &existingParsers[i]
	}

	// process all discovered parsers
	for _, discParser := range discoveredParsers {
		existingParser := existingByParserFunc[discParser.ParserFunction]

		if existingParser == nil {
			// new parser - create with empty capabilities
			updated = append(updated, createTemplateParser(discParser))
			newParserFuncs = append(newParserFuncs, discParser.ParserFunction)
		} else {
			// update auto-gen fields, preserve capabilities
			p := *existingParser
			p.Detector.Method = discParser.Method
			p.Detector.Criteria = discParser.Criteria

			// only update metadata/package types if discovered parser has them
			// this preserves existing YAML values when no test observations exist
			if len(discParser.MetadataTypes) > 0 {
				p.MetadataTypes = discParser.MetadataTypes
				p.JSONSchemaTypes = discParser.JSONSchemaTypes
			} else if len(p.MetadataTypes) > 0 && len(p.JSONSchemaTypes) == 0 {
				// fallback: if parser has metadata_types but no json_schema_types, convert them
				p.JSONSchemaTypes = convertToJSONSchemaTypesFromMetadata(p.MetadataTypes)
			}

			if len(discParser.PackageTypes) > 0 {
				p.PackageTypes = discParser.PackageTypes
			}

			// p.Capabilities is preserved from existing
			updated = append(updated, p)
		}

		// mark this parser as processed
		delete(existingByParserFunc, discParser.ParserFunction)
	}

	// any remaining existing parsers are orphans (parser function was renamed/deleted)
	for parserFunc := range existingByParserFunc {
		orphans = append(orphans, orphanInfo{
			catalogerName:  catalogerName,
			parserFunction: parserFunc,
		})
	}

	return updated, orphans, newParserFuncs
}

func createTemplateEntry(disc DiscoveredCataloger, info *capabilities.CatalogerInfo) capabilities.CatalogerEntry {
	// determine type, checking for overrides first
	catalogerType := disc.Type
	if overrideType, hasOverride := catalogerTypeOverrides[disc.Name]; hasOverride {
		catalogerType = overrideType
	}

	entry := capabilities.CatalogerEntry{
		Ecosystem: inferEcosystem(disc.Name),
		Name:      disc.Name,
		Type:      catalogerType,
		Source: capabilities.Source{
			File:     disc.SourceFile,
			Function: disc.SourceFunction,
		},
	}

	// add selectors from cataloger info
	if info != nil {
		entry.Selectors = info.Selectors
	}

	// use the determined catalogerType (which may be overridden) to structure the entry
	switch catalogerType {
	case genericCatalogerType:
		for _, discParser := range disc.Parsers {
			entry.Parsers = append(entry.Parsers, createTemplateParser(discParser))
		}
	case "custom":
		// custom cataloger with empty capabilities (must be filled manually)
		entry.Capabilities = capabilities.CapabilitySet{}
	}

	return entry
}

func createTemplateParser(disc DiscoveredParser) capabilities.Parser {
	return capabilities.Parser{
		ParserFunction: disc.ParserFunction,
		Detector: capabilities.Detector{
			Method:   disc.Method,
			Criteria: disc.Criteria,
		},
		MetadataTypes:   disc.MetadataTypes,
		PackageTypes:    disc.PackageTypes,
		JSONSchemaTypes: disc.JSONSchemaTypes,
		Capabilities:    capabilities.CapabilitySet{}, // empty array - must be filled manually
	}
}

func formatOrphans(orphans []orphanInfo) string {
	var lines []string
	for _, o := range orphans {
		lines = append(lines, fmt.Sprintf("  - cataloger: %s, parser function: %s", o.catalogerName, o.parserFunction))
	}
	return strings.Join(lines, "\n")
}
