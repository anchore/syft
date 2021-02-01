package cpe

import (
	"github.com/anchore/syft/internal/config"
	"path/filepath"
	"testing"
)

func TestIsUpdateAvailable(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected bool
		err      bool
	}{
		{
			name:     "update available with old data",
			fixture:  "test-fixtures/old-metadata",
			expected: true,
			err:      false,
		},
		{
			name:     "update not available with recent data",
			fixture:  "test-fixtures/recent-metadata",
			expected: false,
			err:      false,
		},
		{
			name:     "update is available with no data",
			fixture:  "test-fixtures/non-existent-metadata",
			expected: true,
			err:      false,
		},
	}

	updateUrl, _ := filepath.Abs("test-fixtures/official-cpe-dictionary_v2.3.xml.gz")
	cpeDictionaryConfig := config.CPEDictionary{
		UpdateURL:        updateUrl,
		AutoUpdate:       false,
		ValidateChecksum: false,
		MinimumScore:     1,
		SpecificVendors:  []config.SpecificMatch{},
		SpecificProducts: []config.SpecificMatch{},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cpeDictionaryConfig.CacheDir = test.fixture
			curator := NewCurator(cpeDictionaryConfig)
			actual, _, err := curator.IsUpdateAvailable()

			if err != nil && !test.err {
				t.Fatalf("failed to check for update: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected error but got none")
			}

			if actual != test.expected {
				t.Errorf("update available difference: %t", actual)
			}
		})
	}
}
