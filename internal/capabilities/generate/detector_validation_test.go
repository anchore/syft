package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDetectorConfigFieldReferences validates that config field names referenced in detector
// conditions actually exist in the cataloger's config struct
func TestDetectorConfigFieldReferences(t *testing.T) {
	repoRoot, err := RepoRoot()
	require.NoError(t, err)

	// load the packages.yaml
	doc, _, err := loadCapabilities(filepath.Join(repoRoot, "internal/capabilities/packages.yaml"))
	require.NoError(t, err)

	// collect all validation errors before failing
	var errors []string

	// check each cataloger's detectors
	for _, cataloger := range doc.Catalogers {
		if cataloger.Type != "custom" {
			continue // only custom catalogers have detectors
		}

		for detectorIdx, detector := range cataloger.Detectors {
			// if detector has no conditions, skip validation
			if len(detector.Conditions) == 0 {
				continue
			}

			// detector has conditions - cataloger must have a config
			if cataloger.Config == "" {
				errors = append(errors,
					fmt.Sprintf("Cataloger %q detector %d has conditions but cataloger has no config struct",
						cataloger.Name, detectorIdx))
				continue
			}

			// load the cataloger's config struct
			configEntry, exists := doc.Configs[cataloger.Config]
			if !exists {
				errors = append(errors,
					fmt.Sprintf("Cataloger %q references config %q which doesn't exist",
						cataloger.Name, cataloger.Config))
				continue
			}

			// build a set of valid config field names
			validFields := make(map[string]bool)
			for _, field := range configEntry.Fields {
				validFields[field.Key] = true
			}

			// validate each condition
			for condIdx, condition := range detector.Conditions {
				for fieldName := range condition.When {
					if !validFields[fieldName] {
						errors = append(errors,
							fmt.Sprintf("Cataloger %q detector %d condition %d references config field %q which doesn't exist in config struct %q",
								cataloger.Name, detectorIdx, condIdx, fieldName, cataloger.Config))
					}
				}
			}
		}
	}

	// report all errors at once
	if len(errors) > 0 {
		require.Fail(t, "Detector config field reference validation failed", strings.Join(errors, "\n"))
	}
}
