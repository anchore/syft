package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/pkg"
)

// requireParserObservations controls whether TestAllCatalogersHaveObservations enforces that all parsers have observations
// - true: fail test if any parser is missing observations (strict mode)
// - false: only check custom catalogers, skip parser checks (lenient mode, not all parsers are observable)
const requireParserObservations = false

// metadataTypeCoverageExceptions lists metadata types that are allowed to not be represented in any cataloger
var metadataTypeCoverageExceptions = strset.New(
	reflect.TypeOf(pkg.MicrosoftKbPatch{}).Name(),
)

// packageTypeCoverageExceptions lists package types that are allowed to not be represented in any cataloger
var packageTypeCoverageExceptions = strset.New(
	string(pkg.JenkinsPluginPkg), // TODO: this should probably be covered by a cataloger test one day
	string(pkg.KbPkg),
)

// observationExceptions maps cataloger/parser names to observation types that should be ignored during validation
//
// TestAllCatalogersHaveObservations:
//   - always checks custom catalogers
//   - checks parsers only if requireParserObservations=true
//   - nil or non-nil value: skip existence check for this cataloger/parser
//
// examples:
//
//	"graalvm-native-image-cataloger": nil,  // custom cataloger: skip existence check
//	"linux-kernel-cataloger": strset.New("relationships"),  // custom cataloger: skip only relationships validation
//	"conan-cataloger/parseConanLock": nil,  // parser: skip all observation validation
//	"cataloger-name/parser-function": strset.New("file_digests"),  // parser: skip only file_digests validation
var observationExceptions = map[string]*strset.Set{
	// for the graalvm-native-image-cataloger, we don't have a really reliable test fixture yet
	"graalvm-native-image-cataloger": nil,
	// the linux-kernel-cataloger produces relationships but aren't really indicative of dependency information in the way the user might expect
	"linux-kernel-cataloger": strset.New("relationships"),
}

func TestCatalogersInSync(t *testing.T) {
	// get canonical list from syft binary
	catalogersInBinary := getCatalogerNamesFromBinary(t)

	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	yamlCatalogers := strset.New()
	for _, c := range catalogerEntries {
		yamlCatalogers.Add(c.Name)
	}

	// test 1: All catalogers in binary must be in YAML
	var missingFromYAML []string
	for _, name := range catalogersInBinary {
		if !yamlCatalogers.Has(name) {
			missingFromYAML = append(missingFromYAML, name)
		}
	}
	require.Empty(t, missingFromYAML,
		"The following catalogers are in 'syft cataloger list' but missing from capabilities YAML: %v\n"+
			"Run 'go generate ./internal/capabilities' to auto-add generic catalogers, or manually add custom catalogers.",
		missingFromYAML)

	// test 2: All catalogers in YAML must exist in binary
	var orphanedInYAML []string
	binarySet := strset.New()
	for _, name := range catalogersInBinary {
		binarySet.Add(name)
	}
	for _, name := range yamlCatalogers.List() {
		if !binarySet.Has(name) {
			orphanedInYAML = append(orphanedInYAML, name)
		}
	}
	require.Empty(t, orphanedInYAML,
		"The following catalogers are in capabilities YAML but not found in binary: %v\n"+
			"These catalogers may have been removed. Delete them from the YAML.",
		orphanedInYAML)

	// test 3: All capabilities must be filled (no TODOs/nulls)
	validateCapabilitiesFilled(t, catalogerEntries)
}

func getCatalogerNamesFromBinary(t *testing.T) []string {
	// get cataloger names from task factories
	infos, err := allPackageCatalogerInfo()
	require.NoError(t, err)

	var names []string
	for _, info := range infos {
		names = append(names, info.Name)
	}

	sort.Strings(names)
	return names
}

func validateCapabilitiesFilled(t *testing.T, catalogers []capabilities.CatalogerEntry) {
	for _, cataloger := range catalogers {
		cataloger := cataloger // capture loop variable for subtest

		t.Run(cataloger.Name, func(t *testing.T) {
			if cataloger.Type == "generic" {
				// generic catalogers have parsers with capabilities
				require.NotEmpty(t, cataloger.Parsers, "generic cataloger must have at least one parser")

				for _, parser := range cataloger.Parsers {
					parser := parser // capture loop variable for subtest

					t.Run(parser.ParserFunction, func(t *testing.T) {
						require.NotEmpty(t, parser.Capabilities, "parser must have at least one capability field defined")
					})
				}
			} else if cataloger.Type == "custom" {
				// custom catalogers have cataloger-level capabilities
				require.NotEmpty(t, cataloger.Capabilities, "custom cataloger must have at least one capability field defined")
			}
		})
	}
}

func TestPackageTypeCoverage(t *testing.T) {
	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// collect all package types mentioned in catalogers
	foundPkgTypes := strset.New()
	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				for _, pkgType := range parser.PackageTypes {
					foundPkgTypes.Add(pkgType)
				}
			}
		} else if cataloger.Type == "custom" {
			for _, pkgType := range cataloger.PackageTypes {
				foundPkgTypes.Add(pkgType)
			}
		}
	}

	// check that all known package types are represented
	var missingTypes []pkg.Type
	for _, pkgType := range pkg.AllPkgs {
		if !foundPkgTypes.Has(string(pkgType)) {
			missingTypes = append(missingTypes, pkgType)
		}
	}

	// filter out exceptions
	var missingTypesWithoutExceptions []pkg.Type
	for _, pkgType := range missingTypes {
		if !packageTypeCoverageExceptions.Has(string(pkgType)) {
			missingTypesWithoutExceptions = append(missingTypesWithoutExceptions, pkgType)
		}
	}

	require.Empty(t, missingTypesWithoutExceptions,
		"The following package types are not represented in any cataloger: %v\n"+
			"Either add catalogers for these types or update pkg.AllPkgs if they're no longer supported.",
		missingTypesWithoutExceptions)
}

func TestMetadataTypeCoverage(t *testing.T) {
	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// collect all metadata types mentioned in catalogers
	foundMetadataTypes := strset.New()
	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				for _, metadataType := range parser.MetadataTypes {
					foundMetadataTypes.Add(strings.TrimPrefix(metadataType, "pkg."))
				}
			}
		} else if cataloger.Type == "custom" {
			for _, metadataType := range cataloger.MetadataTypes {
				foundMetadataTypes.Add(strings.TrimPrefix(metadataType, "pkg."))
			}
		}
	}

	// get all known metadata types
	allMetadataTypes := packagemetadata.AllTypes()

	// check that all known metadata types are represented
	var missingTypes []string
	for _, metadataType := range allMetadataTypes {
		typeName := reflect.TypeOf(metadataType).Name()
		if !foundMetadataTypes.Has(typeName) {
			missingTypes = append(missingTypes, typeName)
		}
	}

	// filter out exceptions
	var missingTypesWithoutExceptions []string
	for _, metadataType := range missingTypes {
		if !metadataTypeCoverageExceptions.Has(metadataType) {
			missingTypesWithoutExceptions = append(missingTypesWithoutExceptions, metadataType)
		}
	}

	require.Empty(t, missingTypesWithoutExceptions,
		"The following metadata types are not represented in any cataloger: %v\n"+
			"Either add catalogers for these types or update packagemetadata.AllTypes() if they're no longer supported.",
		missingTypesWithoutExceptions)
}

func TestCatalogerStructure(t *testing.T) {
	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	for _, cataloger := range catalogerEntries {
		cataloger := cataloger // capture loop variable for subtest

		t.Run(cataloger.Name, func(t *testing.T) {
			// ecosystem must always be set (it's MANUAL)
			require.NotEmpty(t, cataloger.Ecosystem, "ecosystem must be set for all catalogers")

			if cataloger.Type == "generic" {
				// generic catalogers must have parsers
				require.NotEmpty(t, cataloger.Parsers, "generic cataloger must have at least one parser")

				// generic catalogers should not have cataloger-level capabilities
				require.Empty(t, cataloger.Capabilities, "generic cataloger should not have cataloger-level capabilities (use parser-level instead)")

				// generic catalogers should not have cataloger-level metadata/package types
				require.Empty(t, cataloger.MetadataTypes, "generic cataloger should not have cataloger-level metadata types")
				require.Empty(t, cataloger.PackageTypes, "generic cataloger should not have cataloger-level package types")
			} else if cataloger.Type == "custom" {
				// custom catalogers must have detectors
				require.NotEmpty(t, cataloger.Detectors, "custom cataloger must have at least one detector")

				// custom catalogers must have cataloger-level capabilities
				require.NotEmpty(t, cataloger.Capabilities, "custom cataloger must have cataloger-level capabilities")

				// custom catalogers should not have parsers
				require.Empty(t, cataloger.Parsers, "custom cataloger should not have parsers (those are for generic catalogers)")
			} else {
				t.Errorf("unknown cataloger type: %q (must be 'generic' or 'custom')", cataloger.Type)
			}
		})
	}
}

func TestCatalogerDataQuality(t *testing.T) {
	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	t.Run("no duplicate cataloger names", func(t *testing.T) {
		nameCount := make(map[string]int)
		for _, cataloger := range catalogerEntries {
			nameCount[cataloger.Name]++
		}

		var duplicates []string
		for name, count := range nameCount {
			if count > 1 {
				duplicates = append(duplicates, fmt.Sprintf("%s (appears %d times)", name, count))
			}
		}

		require.Empty(t, duplicates, "Found duplicate cataloger names: %v", duplicates)
	})

	t.Run("detector validation for custom catalogers", func(t *testing.T) {
		for _, cataloger := range catalogerEntries {
			if cataloger.Type != "custom" {
				continue
			}

			cataloger := cataloger // capture loop variable

			t.Run(cataloger.Name, func(t *testing.T) {
				require.NotEmpty(t, cataloger.Detectors, "custom cataloger must have at least one detector")

				for i, detector := range cataloger.Detectors {
					t.Run(fmt.Sprintf("detector-%d", i), func(t *testing.T) {
						// detector criteria must not be empty
						require.NotEmpty(t, detector.Criteria, "detector criteria must not be empty")

						// detector method must be valid
						validMethods := map[capabilities.ArtifactDetectionMethod]bool{
							capabilities.GlobDetection:     true,
							capabilities.PathDetection:     true,
							capabilities.MIMETypeDetection: true,
						}
						require.True(t, validMethods[detector.Method],
							"detector method must be one of: glob, path, mimetype (got %q)", detector.Method)
					})
				}
			})
		}
	})

	t.Run("no duplicate parser functions within cataloger", func(t *testing.T) {
		for _, cataloger := range catalogerEntries {
			if cataloger.Type != "generic" {
				continue
			}

			cataloger := cataloger // capture loop variable

			t.Run(cataloger.Name, func(t *testing.T) {
				parserFuncs := strset.New()
				var duplicates []string

				for _, parser := range cataloger.Parsers {
					if parserFuncs.Has(parser.ParserFunction) {
						duplicates = append(duplicates, parser.ParserFunction)
					}
					parserFuncs.Add(parser.ParserFunction)
				}

				require.Empty(t, duplicates, "Found duplicate parser functions: %v", duplicates)
			})
		}
	})
}

// TestRegenerateCapabilitiesDoesNotFail verifies that regeneration runs successfully
func TestRegenerateCapabilitiesDoesNotFail(t *testing.T) {
	if os.Getenv("CI") == "" {
		t.Skip("skipping regeneration test in local environment")
	}

	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	yamlPath := filepath.Join(repoRoot, "internal/capabilities/packages.yaml")

	// regenerate should not fail
	_, err = RegenerateCapabilities(yamlPath, repoRoot)
	require.NoError(t, err)

	// verify file hasn't changed (i.e., it was already up to date)
	cmd := exec.Command("git", "diff", "--exit-code", yamlPath)
	cmd.Dir = repoRoot
	err = cmd.Run()
	require.NoError(t, err, "packages.yaml has uncommitted changes after regeneration. Run 'go generate ./internal/capabilities' locally and commit the changes.")
}

// TestAllCatalogersHaveObservations verifies that all catalogers have test observations,
// ensuring they are using the pkgtest helpers
func TestAllCatalogersHaveObservations(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load catalogers from YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// collect all catalogers and parsers from observations
	observedCatalogers := strset.New()
	observedParsers := make(map[string]*strset.Set) // package -> parser set

	// walk test-fixtures directories to find test-observations.json files
	testFixtureDirs, err := findTestFixtureDirs(repoRoot)
	require.NoError(t, err)

	for _, dir := range testFixtureDirs {
		observationsFile := filepath.Join(dir, "test-observations.json")
		if _, err := os.Stat(observationsFile); os.IsNotExist(err) {
			continue
		}

		observations, err := readTestObservations(observationsFile)
		if err != nil {
			t.Logf("Warning: failed to read %s: %v", observationsFile, err)
			continue
		}

		// track observed catalogers
		for catalogerName := range observations.Catalogers {
			observedCatalogers.Add(catalogerName)
		}

		// track observed parsers
		pkg := observations.Package
		if observedParsers[pkg] == nil {
			observedParsers[pkg] = strset.New()
		}
		for parserName := range observations.Parsers {
			observedParsers[pkg].Add(parserName)
		}
	}

	// infer parser observations for single-parser catalogers
	// if a cataloger has only one parser and the cataloger was observed, assume the parser was evaluated
	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "generic" && len(cataloger.Parsers) == 1 && observedCatalogers.Has(cataloger.Name) {
			packageName := extractPackageName(cataloger.Name)
			if observedParsers[packageName] == nil {
				observedParsers[packageName] = strset.New()
			}
			observedParsers[packageName].Add(cataloger.Parsers[0].ParserFunction)
		}
	}

	// verify catalogers have observations
	var missingCatalogers []string
	var missingParsers []string

	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "custom" {
			// custom catalogers should always have cataloger-level observations
			// skip if this cataloger has an exception (nil or non-nil)
			if _, hasException := observationExceptions[cataloger.Name]; hasException {
				continue
			}
			if !observedCatalogers.Has(cataloger.Name) {
				missingCatalogers = append(missingCatalogers, cataloger.Name)
			}
		} else if cataloger.Type == "generic" && requireParserObservations {
			// generic catalogers have parser-level observations (only checked if requireParserObservations=true)
			// skip if the cataloger itself has an exception (applies to all its parsers)
			if _, hasException := observationExceptions[cataloger.Name]; hasException {
				continue
			}

			// extract package name from cataloger name
			packageName := extractPackageName(cataloger.Name)

			for _, parser := range cataloger.Parsers {
				parserKey := fmt.Sprintf("%s/%s", cataloger.Name, parser.ParserFunction)
				// skip if this specific parser has an exception (nil or non-nil)
				if _, hasException := observationExceptions[parserKey]; hasException {
					continue
				}
				if observedParsers[packageName] == nil || !observedParsers[packageName].Has(parser.ParserFunction) {
					missingParsers = append(missingParsers, parserKey)
				}
			}
		}
	}

	require.Empty(t, missingCatalogers,
		"The following custom catalogers have no test observations (not using pkgtest helpers): %v\n"+
			"Update tests to use CatalogTester.TestCataloger() from syft/pkg/cataloger/internal/pkgtest",
		missingCatalogers)

	if requireParserObservations {
		require.Empty(t, missingParsers,
			"The following parsers have no test observations (not using pkgtest helpers): %v\n"+
				"Update tests to use CatalogTester.TestParser() from syft/pkg/cataloger/internal/pkgtest",
			missingParsers)
	}
}

// extractPackageName extracts the package name from a cataloger name
// e.g., "javascript-lock-cataloger" -> "javascript"
func extractPackageName(catalogerName string) string {
	// package name is the first segment before the first dash
	for i, ch := range catalogerName {
		if ch == '-' {
			return catalogerName[:i]
		}
	}
	return catalogerName
}

func TestConfigCompleteness(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := loadCapabilities(filepath.Join(repoRoot, "internal/capabilities/packages.yaml"))
	require.NoError(t, err)

	// collect all validation errors before failing
	var errors []string

	// validation 1: all entries in configs section are referenced by at least one cataloger
	configsReferenced := make(map[string]bool)
	for _, cataloger := range doc.Catalogers {
		if cataloger.Config != "" {
			configsReferenced[cataloger.Config] = true
		}
	}

	for configKey := range doc.Configs {
		if !configsReferenced[configKey] {
			errors = append(errors, fmt.Sprintf("Config %q is not referenced by any cataloger", configKey))
		}
	}

	// validation 2: all catalogers with non-empty config field have entry in configs
	for _, cataloger := range doc.Catalogers {
		if cataloger.Config != "" {
			if _, exists := doc.Configs[cataloger.Config]; !exists {
				errors = append(errors, fmt.Sprintf("Cataloger %q references config %q which doesn't exist in configs section", cataloger.Name, cataloger.Config))
			}
		}
	}

	// validation 3: all app-key references in configs exist in app-config section
	// build a set of all app-config keys for quick lookup
	appConfigKeys := make(map[string]bool)
	for _, appConfig := range doc.ApplicationConfig {
		appConfigKeys[appConfig.Key] = true
	}

	for configName, configEntry := range doc.Configs {
		for _, field := range configEntry.Fields {
			if field.AppKey != "" {
				if !appConfigKeys[field.AppKey] {
					errors = append(errors, fmt.Sprintf("Config field %q.%s references app-key %q which doesn't exist in app-config section", configName, field.Key, field.AppKey))
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Config completeness validation failed", strings.Join(errors, "\n"))
	}
}

func TestAppConfigFieldsHaveDescriptions(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	configs, err := DiscoverAppConfigs(repoRoot)
	require.NoError(t, err)

	// verify that all configs have descriptions
	var missingDescriptions []string
	for _, cfg := range configs {
		if cfg.Description == "" {
			missingDescriptions = append(missingDescriptions, cfg.Key)
		}
	}

	require.Empty(t, missingDescriptions, "the following configs are missing descriptions: %v", missingDescriptions)
}

func TestAppConfigKeyFormat(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	configs, err := DiscoverAppConfigs(repoRoot)
	require.NoError(t, err)

	// verify that all config keys follow the expected format
	for _, cfg := range configs {
		// keys should be in format "ecosystem.field-name" or "ecosystem.nested.field-name"
		require.Contains(t, cfg.Key, ".", "config key should contain at least one dot: %s", cfg.Key)

		// keys should use kebab-case (all lowercase with hyphens)
		require.NotContains(t, cfg.Key, "_", "config key should not contain underscores: %s", cfg.Key)
		require.NotContains(t, cfg.Key, " ", "config key should not contain spaces: %s", cfg.Key)
	}
}

// TestCapabilityConfigFieldReferences validates that config field names referenced in CapabilitiesV2
// conditions actually exist in the cataloger's config struct
func TestCapabilityConfigFieldReferences(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := loadCapabilities(filepath.Join(repoRoot, "internal/capabilities/packages.yaml"))
	require.NoError(t, err)

	// collect all validation errors before failing
	var errors []string

	// for each cataloger with CapabilitiesV2
	for _, cataloger := range doc.Catalogers {
		// check cataloger-level CapabilitiesV2 (for custom catalogers)
		if cataloger.Type == "custom" && len(cataloger.Capabilities) > 0 {
			// load the cataloger's config struct if it has one
			if cataloger.Config != "" {
				configEntry, exists := doc.Configs[cataloger.Config]
				if !exists {
					errors = append(errors, fmt.Sprintf("Cataloger %q references config %q which doesn't exist", cataloger.Name, cataloger.Config))
					continue
				}

				// build a set of valid config field names
				validFields := make(map[string]bool)
				for _, field := range configEntry.Fields {
					validFields[field.Key] = true
				}

				// validate each capability field
				for _, capField := range cataloger.Capabilities {
					// check conditions for config field references
					for _, condition := range capField.Conditions {
						for fieldName := range condition.When {
							if !validFields[fieldName] {
								errors = append(errors,
									fmt.Sprintf("Cataloger %q capability field %q references config field %q which doesn't exist in config struct %q",
										cataloger.Name, capField.Name, fieldName, cataloger.Config))
							}
						}
					}
				}
			} else if len(cataloger.Capabilities) > 0 {
				// cataloger has CapabilitiesV2 with conditions but no config - check if any conditions reference fields
				for _, capField := range cataloger.Capabilities {
					if len(capField.Conditions) > 0 {
						for _, condition := range capField.Conditions {
							if len(condition.When) > 0 {
								errors = append(errors,
									fmt.Sprintf("Cataloger %q capability field %q has conditions but cataloger has no config struct",
										cataloger.Name, capField.Name))
								break
							}
						}
					}
				}
			}
		}

		// check parser-level CapabilitiesV2 (for generic catalogers)
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				if len(parser.Capabilities) > 0 {
					// load the cataloger's config struct if it has one
					if cataloger.Config != "" {
						configEntry, exists := doc.Configs[cataloger.Config]
						if !exists {
							errors = append(errors, fmt.Sprintf("Cataloger %q references config %q which doesn't exist", cataloger.Name, cataloger.Config))
							continue
						}

						// build a set of valid config field names
						validFields := make(map[string]bool)
						for _, field := range configEntry.Fields {
							validFields[field.Key] = true
						}

						// validate each capability field
						for _, capField := range parser.Capabilities {
							// check conditions for config field references
							for _, condition := range capField.Conditions {
								for fieldName := range condition.When {
									if !validFields[fieldName] {
										errors = append(errors,
											fmt.Sprintf("Parser %q/%s capability field %q references config field %q which doesn't exist in config struct %q",
												cataloger.Name, parser.ParserFunction, capField.Name, fieldName, cataloger.Config))
									}
								}
							}
						}
					} else {
						// parser has CapabilitiesV2 with conditions but cataloger has no config
						for _, capField := range parser.Capabilities {
							if len(capField.Conditions) > 0 {
								for _, condition := range capField.Conditions {
									if len(condition.When) > 0 {
										errors = append(errors,
											fmt.Sprintf("Parser %q/%s capability field %q has conditions but cataloger has no config struct",
												cataloger.Name, parser.ParserFunction, capField.Name))
										break
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "CapabilityV2 config field reference validation failed", strings.Join(errors, "\n"))
	}
}

// TestCapabilityFieldNaming validates that capability field names follow known patterns
func TestCapabilityFieldNaming(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := loadCapabilities(filepath.Join(repoRoot, "internal/capabilities/packages.yaml"))
	require.NoError(t, err)

	// define known capability field paths
	knownFields := strset.New(
		"license",
		"dependency.depth",
		"dependency.edges",
		"dependency.kinds",
		"package_manager.files.listing",
		"package_manager.files.digests",
		"package_manager.package_integrity_hash",
	)

	// collect all validation errors/warnings
	var errors []string

	// check cataloger-level CapabilitiesV2
	for _, cataloger := range doc.Catalogers {
		if cataloger.Type == "custom" && len(cataloger.Capabilities) > 0 {
			for _, capField := range cataloger.Capabilities {
				if !knownFields.Has(capField.Name) {
					errors = append(errors,
						fmt.Sprintf("Cataloger %q uses unknown capability field %q - may be a typo or new field not in known list",
							cataloger.Name, capField.Name))
				}
			}
		}

		// check parser-level CapabilitiesV2
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				if len(parser.Capabilities) > 0 {
					for _, capField := range parser.Capabilities {
						if !knownFields.Has(capField.Name) {
							errors = append(errors,
								fmt.Sprintf("Parser %q/%s uses unknown capability field %q - may be a typo or new field not in known list",
									cataloger.Name, parser.ParserFunction, capField.Name))
						}
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Capability field naming validation failed", strings.Join(errors, "\n"))
	}
}

// TestCapabilityValueTypes validates that capability field values match expected types
func TestCapabilityValueTypes(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := loadCapabilities(filepath.Join(repoRoot, "internal/capabilities/packages.yaml"))
	require.NoError(t, err)

	// collect all validation errors
	var errors []string

	// validate cataloger-level CapabilitiesV2
	for _, cataloger := range doc.Catalogers {
		if cataloger.Type == "custom" && len(cataloger.Capabilities) > 0 {
			for _, capField := range cataloger.Capabilities {
				// validate default value type
				err := validateCapabilityValueType(capField.Name, capField.Default)
				if err != nil {
					errors = append(errors,
						fmt.Sprintf("Cataloger %q capability field %q default value: %v",
							cataloger.Name, capField.Name, err))
				}

				// validate condition value types
				for i, condition := range capField.Conditions {
					err := validateCapabilityValueType(capField.Name, condition.Value)
					if err != nil {
						errors = append(errors,
							fmt.Sprintf("Cataloger %q capability field %q condition %d value: %v",
								cataloger.Name, capField.Name, i, err))
					}
				}
			}
		}

		// validate parser-level CapabilitiesV2
		if cataloger.Type == "generic" {
			for _, parser := range cataloger.Parsers {
				if len(parser.Capabilities) > 0 {
					for _, capField := range parser.Capabilities {
						// validate default value type
						err := validateCapabilityValueType(capField.Name, capField.Default)
						if err != nil {
							errors = append(errors,
								fmt.Sprintf("Parser %q/%s capability field %q default value: %v",
									cataloger.Name, parser.ParserFunction, capField.Name, err))
						}

						// validate condition value types
						for i, condition := range capField.Conditions {
							err := validateCapabilityValueType(capField.Name, condition.Value)
							if err != nil {
								errors = append(errors,
									fmt.Sprintf("Parser %q/%s capability field %q condition %d value: %v",
										cataloger.Name, parser.ParserFunction, capField.Name, i, err))
							}
						}
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Capability value type validation failed", strings.Join(errors, "\n"))
	}
}

// validateCapabilityValueType checks if a value matches the expected type for a capability field
func validateCapabilityValueType(fieldPath string, value interface{}) error {
	if value == nil {
		return nil // nil is acceptable
	}

	switch fieldPath {
	case "license",
		"package_manager.files.listing",
		"package_manager.files.digests",
		"package_manager.package_integrity_hash":
		// expect bool
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("expected bool, got %T", value)
		}

	case "dependency.depth", "dependency.kinds":
		// expect []string or []interface{} that can be converted to []string
		switch v := value.(type) {
		case []string:
			// ok
		case []interface{}:
			// check each element is a string
			for i, elem := range v {
				if _, ok := elem.(string); !ok {
					return fmt.Errorf("expected []string, but element %d is %T", i, elem)
				}
			}
		default:
			return fmt.Errorf("expected []string, got %T", value)
		}

	case "dependency.edges":
		// expect string
		if _, ok := value.(string); !ok {
			return fmt.Errorf("expected string, got %T", value)
		}

	default:
		// unknown field, skip validation
		return nil
	}

	return nil
}

// loadConfigStructFields loads the config struct definition from source code using AST parsing
func loadConfigStructFields(repoRoot, configName string) (map[string]string, error) {
	// configName format: "package.StructName" (e.g., "golang.CatalogerConfig")
	parts := strings.Split(configName, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid config name format: %q", configName)
	}

	packageName := parts[0]
	structName := parts[1]

	// find the package directory
	packageDir := filepath.Join(repoRoot, "syft", "pkg", "cataloger", packageName)
	if _, err := os.Stat(packageDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("package directory not found: %s", packageDir)
	}

	// parse all .go files in the package
	files, err := filepath.Glob(filepath.Join(packageDir, "*.go"))
	if err != nil {
		return nil, err
	}

	for _, filePath := range files {
		if strings.HasSuffix(filePath, "_test.go") {
			continue
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			continue
		}

		// find the struct definition
		fields := findStructFields(file, structName)
		if len(fields) > 0 {
			return fields, nil
		}
	}

	return nil, fmt.Errorf("config struct %q not found in package %q", structName, packageName)
}

// findStructFields extracts field names and types from a struct definition
func findStructFields(file *ast.File, structName string) map[string]string {
	fields := make(map[string]string)

	ast.Inspect(file, func(n ast.Node) bool {
		// look for type declarations
		typeSpec, ok := n.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != structName {
			return true
		}

		// check if it's a struct type
		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			return false
		}

		// extract field names and types
		for _, field := range structType.Fields.List {
			if len(field.Names) == 0 {
				continue // embedded field
			}

			fieldName := field.Names[0].Name
			fieldType := getTypeName(field.Type)
			fields[fieldName] = fieldType
		}

		return false
	})

	return fields
}

// getTypeName extracts a string representation of a type
func getTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return fmt.Sprintf("%s.%s", getTypeName(t.X), t.Sel.Name)
	case *ast.ArrayType:
		return fmt.Sprintf("[]%s", getTypeName(t.Elt))
	case *ast.MapType:
		return fmt.Sprintf("map[%s]%s", getTypeName(t.Key), getTypeName(t.Value))
	case *ast.StarExpr:
		return fmt.Sprintf("*%s", getTypeName(t.X))
	default:
		return "unknown"
	}
}
