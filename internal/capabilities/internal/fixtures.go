package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/anchore/syft/internal/capabilities/pkgtestobservation"
)

// FindTestFixtureDirs walks the cataloger directory tree and returns all test-fixtures directories
func FindTestFixtureDirs(repoRoot string) ([]string, error) {
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

// ReadTestObservations reads and parses a test-observations.json file
func ReadTestObservations(path string) (*pkgtestobservation.Test, error) {
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
