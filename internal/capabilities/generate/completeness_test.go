package main

import (
	"fmt"
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
	"github.com/anchore/syft/internal/capabilities/pkgtestobservation"
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
// TestCapabilityObservationsMatchDeclarations:
//   - nil value: skip ALL observation validation for this cataloger/parser
//   - non-nil set: skip only specific observation types
//     observation types: "license", "relationships", "file_listing", "file_digests", "integrity_hash"
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
						require.NotNil(t, parser.Capabilities, "parser must have capabilities defined")
						require.NotEmpty(t, parser.Capabilities, "parser must have at least one capability mode")

						for mode, cap := range parser.Capabilities {
							mode := mode // capture loop variable for subtest

							t.Run(string(mode), func(t *testing.T) {
								validateCapabilityDescription(t, cap)
							})
						}
					})
				}
			} else if cataloger.Type == "custom" {
				// custom catalogers have cataloger-level capabilities
				require.NotNil(t, cataloger.Capabilities, "custom cataloger must have capabilities defined")
				require.NotEmpty(t, cataloger.Capabilities, "custom cataloger must have at least one capability mode")

				for mode, cap := range cataloger.Capabilities {
					mode := mode // capture loop variable for subtest

					t.Run(string(mode), func(t *testing.T) {
						validateCapabilityDescription(t, cap)
					})
				}
			}
		})
	}
}

func validateCapabilityDescription(t *testing.T, capability *capabilities.Capability) {
	// check that dependency fields are not empty/nil (which would indicate TODO/unset)
	// we allow empty arrays/strings, but not nil
	require.NotNil(t, capability.Dependencies.Reach,
		"Dependencies.Reach must be set (use [] for no dependencies)")
	require.NotNil(t, capability.Dependencies.Kinds,
		"Dependencies.Kinds must be set (use [] for no kinds)")

	// if there are dependencies, topology must be set
	if len(capability.Dependencies.Reach) > 0 || len(capability.Dependencies.Kinds) > 0 {
		require.NotEmpty(t, capability.Dependencies.Topology,
			"Dependencies.Topology must be set when dependencies are defined")
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

	// TODO: we might want this one day, however, for now it's not strictly necessary (and not complete yet)
	//t.Run("source validation", func(t *testing.T) {
	//	for _, cataloger := range catalogerEntries {
	//		cataloger := cataloger // capture loop variable
	//
	//		t.Run(cataloger.Name, func(t *testing.T) {
	//			require.NotEmpty(t, cataloger.Source.File, "source file must be set")
	//			require.NotEmpty(t, cataloger.Source.Function, "source function must be set")
	//		})
	//	}
	//})

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

func TestFileOwnerCapabilities(t *testing.T) {
	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// get all metadata types and check which implement FileOwner
	allMetadataTypes := packagemetadata.AllTypes()
	fileOwnerTypes := strset.New()

	for _, metadataType := range allMetadataTypes {
		// check if this type implements pkg.FileOwner
		if _, ok := metadataType.(pkg.FileOwner); ok {
			typeName := reflect.TypeOf(metadataType).Name()
			fileOwnerTypes.Add(typeName)
		}
	}

	// for each cataloger entry, check if any of its metadata types implement FileOwner
	for _, cataloger := range catalogerEntries {
		cataloger := cataloger // capture loop variable

		if cataloger.Type == "generic" {
			// check each parser's metadata types
			for _, parser := range cataloger.Parsers {
				parser := parser // capture loop variable

				// check if any metadata types implement FileOwner
				hasFileOwner := false
				for _, metadataType := range parser.MetadataTypes {
					if fileOwnerTypes.Has(metadataType) {
						hasFileOwner = true
						break
					}
				}

				if hasFileOwner {
					t.Run(fmt.Sprintf("%s/%s", cataloger.Name, parser.ParserFunction), func(t *testing.T) {
						// must have offline capability
						require.Contains(t, parser.Capabilities, capabilities.OfflineMode,
							"parser with FileOwner metadata must have offline capability")

						offlineCap := parser.Capabilities[capabilities.OfflineMode]
						require.NotNil(t, offlineCap, "offline capability must not be nil")

						// package_manager.files.listing must be true
						require.NotNil(t, offlineCap.PackageManager, "package_manager must not be nil")
						require.NotNil(t, offlineCap.PackageManager.Files, "package_manager.files must not be nil")
						require.NotNil(t, offlineCap.PackageManager.Files.Listing, "package_manager.files.listing must not be nil")
						require.True(t, *offlineCap.PackageManager.Files.Listing,
							"parser with FileOwner metadata must have package_manager.files.listing set to true in offline mode")
					})
				}
			}
		} else if cataloger.Type == "custom" {
			// check cataloger-level metadata types
			hasFileOwner := false
			for _, metadataType := range cataloger.MetadataTypes {
				if fileOwnerTypes.Has(metadataType) {
					hasFileOwner = true
					break
				}
			}

			if hasFileOwner {
				t.Run(cataloger.Name, func(t *testing.T) {
					// must have offline capability
					require.Contains(t, cataloger.Capabilities, capabilities.OfflineMode,
						"cataloger with FileOwner metadata must have offline capability")

					offlineCap := cataloger.Capabilities[capabilities.OfflineMode]
					require.NotNil(t, offlineCap, "offline capability must not be nil")

					// package_manager.files.listing must be true
					require.NotNil(t, offlineCap.PackageManager, "package_manager must not be nil")
					require.NotNil(t, offlineCap.PackageManager.Files, "package_manager.files must not be nil")
					require.NotNil(t, offlineCap.PackageManager.Files.Listing, "package_manager.files.listing must not be nil")
					require.True(t, *offlineCap.PackageManager.Files.Listing,
						"cataloger with FileOwner metadata must have package_manager.files.listing set to true in offline mode")
				})
			}
		}
	}
}

func TestCapabilityValues(t *testing.T) {
	// load catalogers from embedded YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// valid enrichment modes
	validModes := strset.New(
		string(capabilities.OfflineMode),
		string(capabilities.OnlineMode),
		string(capabilities.ToolExecutionMode),
	)

	// valid topology values
	validTopologies := strset.New(
		"none",     // no dependencies
		"flat",     // edges from root to all nodes as single level of dependencies
		"reduced",  // transitive reduction (no redundant edges) or other form of non-complete edges
		"complete", // all edges between dependencies are represented accurately
		"",         // allow empty string when there are no dependencies
	)

	// valid reach values
	validReach := strset.New(
		"direct",
		"indirect",
	)

	for _, cataloger := range catalogerEntries {
		cataloger := cataloger // capture loop variable

		t.Run(cataloger.Name, func(t *testing.T) {
			// collect capabilities from either cataloger-level or parser-level
			var capsToValidate map[capabilities.EnrichmentMode]*capabilities.Capability

			if cataloger.Type == "generic" {
				// validate each parser's capabilities
				for _, parser := range cataloger.Parsers {
					parser := parser // capture loop variable

					t.Run(parser.ParserFunction, func(t *testing.T) {
						capsToValidate = parser.Capabilities
						validateCapabilityValues(t, capsToValidate, validModes, validTopologies, validReach)
					})
				}
			} else if cataloger.Type == "custom" {
				capsToValidate = cataloger.Capabilities
				validateCapabilityValues(t, capsToValidate, validModes, validTopologies, validReach)
			}
		})
	}
}

func validateCapabilityValues(
	t *testing.T,
	caps map[capabilities.EnrichmentMode]*capabilities.Capability,
	validModes *strset.Set,
	validTopologies *strset.Set,
	validReach *strset.Set,
) {
	for mode, cap := range caps {
		mode := mode // capture loop variable

		t.Run(string(mode), func(t *testing.T) {
			// enrichment mode must be valid
			require.True(t, validModes.Has(string(mode)),
				"enrichment mode must be one of: 'offline', 'online', 'tool-execution' (got %q)", mode)

			// topology must be valid
			require.True(t, validTopologies.Has(cap.Dependencies.Topology),
				"topology must be one of: 'flat', 'reduced', 'complete', or 'none' (got %q)", cap.Dependencies.Topology)

			// reach values must be valid
			for _, reach := range cap.Dependencies.Reach {
				require.True(t, validReach.Has(reach),
					"reach value must be 'direct' or 'indirect' (got %q)", reach)
			}
		})
	}
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

// TestCapabilityObservationsMatchDeclarations verifies that observed capabilities during tests
// match what's declared in packages.yaml
func TestCapabilityObservationsMatchDeclarations(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load catalogers from YAML
	catalogerEntries, err := capabilities.Packages()
	require.NoError(t, err)

	// create lookup maps for capabilities
	catalogerCaps := make(map[string]map[capabilities.EnrichmentMode]*capabilities.Capability)
	parserCaps := make(map[string]map[string]map[capabilities.EnrichmentMode]*capabilities.Capability) // cataloger -> parser -> mode -> capability

	for _, cataloger := range catalogerEntries {
		if cataloger.Type == "custom" {
			catalogerCaps[cataloger.Name] = cataloger.Capabilities
		} else if cataloger.Type == "generic" {
			if parserCaps[cataloger.Name] == nil {
				parserCaps[cataloger.Name] = make(map[string]map[capabilities.EnrichmentMode]*capabilities.Capability)
			}
			for _, parser := range cataloger.Parsers {
				parserCaps[cataloger.Name][parser.ParserFunction] = parser.Capabilities
			}
		}
	}

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

		// validate cataloger observations
		for catalogerName, catalogerObs := range observations.Catalogers {
			t.Run(fmt.Sprintf("cataloger/%s", catalogerName), func(t *testing.T) {
				caps, found := catalogerCaps[catalogerName]
				if !found {
					t.Skipf("cataloger %s not found in YAML (may be a generic cataloger)", catalogerName)
					return
				}

				validateObservationsMatchCapabilities(t, catalogerName, catalogerObs.Observations, caps)
			})
		}

		// validate parser observations
		for parserName, parserObs := range observations.Parsers {
			// find all catalogers that use this parser
			found := false
			for catalogerName, parsers := range parserCaps {
				if caps, ok := parsers[parserName]; ok {
					found = true
					t.Run(fmt.Sprintf("parser/%s/%s", catalogerName, parserName), func(t *testing.T) {
						validateObservationsMatchCapabilities(t, fmt.Sprintf("%s/%s", catalogerName, parserName), parserObs.Observations, caps)
					})
				}
			}

			if !found {
				t.Run(fmt.Sprintf("parser/%s/%s", observations.Package, parserName), func(t *testing.T) {
					t.Skipf("parser %s not found in any cataloger capabilities", parserName)
				})
			}
		}
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

// shouldIgnoreObservation checks if a specific observation type should be ignored for a given cataloger/parser
func shouldIgnoreObservation(name string, observationType string) bool {
	if exceptions, ok := observationExceptions[name]; ok {
		return exceptions.Has(observationType)
	}
	return false
}

// validateObservationsMatchCapabilities checks that test observations match declared capabilities
func validateObservationsMatchCapabilities(
	t *testing.T,
	name string,
	obs pkgtestobservation.Observations,
	caps map[capabilities.EnrichmentMode]*capabilities.Capability,
) {
	// check offline mode capabilities
	offlineCap, hasOffline := caps[capabilities.OfflineMode]
	if !hasOffline {
		// if there's no offline capability, we can't validate much
		return
	}

	// validate license observations
	if obs.License && !shouldIgnoreObservation(name, "license") {
		require.NotNil(t, offlineCap.License,
			"%s: tests show license observations, but capability has no license field", name)
		require.True(t, *offlineCap.License,
			"%s: tests show license observations, but capability has license set to false", name)
	}

	// validate relationship observations
	if obs.Relationships.Count > 0 && !shouldIgnoreObservation(name, "relationships") {
		require.NotNil(t, offlineCap.Dependencies,
			"%s: tests show %d relationship observations, but capability has no dependencies section",
			name, obs.Relationships.Count)

		// if we have relationships, we should have at least some reach or kinds defined
		hasReach := len(offlineCap.Dependencies.Reach) > 0
		hasKinds := len(offlineCap.Dependencies.Kinds) > 0
		require.True(t, hasReach || hasKinds,
			"%s: tests show %d relationship observations, but capability declares no dependency reach or kinds",
			name, obs.Relationships.Count)
	}

	// validate file listing observations
	if obs.FileListing.Count > 0 && !shouldIgnoreObservation(name, "file_listing") {
		require.NotNil(t, offlineCap.PackageManager,
			"%s: tests show %d packages with file listings, but capability has no package_manager section",
			name, obs.FileListing.Count)
		require.NotNil(t, offlineCap.PackageManager.Files,
			"%s: tests show %d packages with file listings, but capability has no package_manager.files section",
			name, obs.FileListing.Count)
		require.NotNil(t, offlineCap.PackageManager.Files.Listing,
			"%s: tests show %d packages with file listings, but capability has no package_manager.files.listing field",
			name, obs.FileListing.Count)
		require.True(t, *offlineCap.PackageManager.Files.Listing,
			"%s: tests show %d packages with file listings, but capability has package_manager.files.listing set to false",
			name, obs.FileListing.Count)
	}

	// validate file digest observations
	if obs.FileDigests.Count > 0 && !shouldIgnoreObservation(name, "file_digests") {
		require.NotNil(t, offlineCap.PackageManager,
			"%s: tests show %d packages with file digests, but capability has no package_manager section",
			name, obs.FileDigests.Count)
		require.NotNil(t, offlineCap.PackageManager.Files,
			"%s: tests show %d packages with file digests, but capability has no package_manager.files section",
			name, obs.FileDigests.Count)
		require.NotNil(t, offlineCap.PackageManager.Files.Digests,
			"%s: tests show %d packages with file digests, but capability has no package_manager.files.digests field",
			name, obs.FileDigests.Count)
		require.True(t, *offlineCap.PackageManager.Files.Digests,
			"%s: tests show %d packages with file digests, but capability has package_manager.files.digests set to false",
			name, obs.FileDigests.Count)
	}

	// validate integrity hash observations
	if obs.IntegrityHash.Count > 0 && !shouldIgnoreObservation(name, "integrity_hash") {
		require.NotNil(t, offlineCap.PackageManager,
			"%s: tests show %d packages with integrity hashes, but capability has no package_manager section",
			name, obs.IntegrityHash.Count)
		require.NotNil(t, offlineCap.PackageManager.PackageIntegrityHash,
			"%s: tests show %d packages with integrity hashes, but capability has no package_manager.package_integrity_hash field",
			name, obs.IntegrityHash.Count)
		require.True(t, *offlineCap.PackageManager.PackageIntegrityHash,
			"%s: tests show %d packages with integrity hashes, but capability has package_manager.package_integrity_hash set to false",
			name, obs.IntegrityHash.Count)
	}
}
