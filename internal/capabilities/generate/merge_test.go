package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
)

func TestMergeConfigSections(t *testing.T) {
	tests := []struct {
		name               string
		existingDoc        *capabilities.Document
		newConfigs         map[string]capabilities.CatalogerConfigEntry
		newAppConfigs      []capabilities.ApplicationConfigField
		expectedConfigs    map[string]capabilities.CatalogerConfigEntry
		expectedAppConfigs []capabilities.ApplicationConfigField
		description        string
	}{
		{
			name:        "new configs replace existing configs",
			description: "configs and app-config are AUTO-GENERATED, so new data should completely replace old",
			existingDoc: &capabilities.Document{
				Configs: map[string]capabilities.CatalogerConfigEntry{
					"golang.OldConfig": {
						Fields: []capabilities.CatalogerConfigFieldEntry{
							{Key: "OldField", Description: "old field"},
						},
					},
				},
				ApplicationConfig: []capabilities.ApplicationConfigField{
					{Key: "golang.old-config", Description: "old config"},
				},
				Catalogers: []capabilities.CatalogerEntry{},
			},
			newConfigs: map[string]capabilities.CatalogerConfigEntry{
				"golang.CatalogerConfig": {
					Fields: []capabilities.CatalogerConfigFieldEntry{
						{Key: "SearchLocalModCacheLicenses", Description: "search local mod cache", AppKey: "golang.search-local-mod-cache-licenses"},
					},
				},
			},
			newAppConfigs: []capabilities.ApplicationConfigField{
				{Key: "golang.search-local-mod-cache-licenses", Description: "Search licenses in local mod cache", DefaultValue: false},
			},
			expectedConfigs: map[string]capabilities.CatalogerConfigEntry{
				"golang.CatalogerConfig": {
					Fields: []capabilities.CatalogerConfigFieldEntry{
						{Key: "SearchLocalModCacheLicenses", Description: "search local mod cache", AppKey: "golang.search-local-mod-cache-licenses"},
					},
				},
			},
			expectedAppConfigs: []capabilities.ApplicationConfigField{
				{Key: "golang.search-local-mod-cache-licenses", Description: "Search licenses in local mod cache", DefaultValue: false},
			},
		},
		{
			name:        "empty new configs clears existing configs",
			description: "if no configs are discovered, the sections should be empty (not nil)",
			existingDoc: &capabilities.Document{
				Configs: map[string]capabilities.CatalogerConfigEntry{
					"golang.OldConfig": {
						Fields: []capabilities.CatalogerConfigFieldEntry{
							{Key: "OldField", Description: "old field"},
						},
					},
				},
				ApplicationConfig: []capabilities.ApplicationConfigField{
					{Key: "golang.old-config", Description: "old config"},
				},
				Catalogers: []capabilities.CatalogerEntry{},
			},
			newConfigs:         map[string]capabilities.CatalogerConfigEntry{},
			newAppConfigs:      []capabilities.ApplicationConfigField{},
			expectedConfigs:    map[string]capabilities.CatalogerConfigEntry{},
			expectedAppConfigs: []capabilities.ApplicationConfigField{},
		},
		{
			name:        "nil existing configs are replaced with new configs",
			description: "first-time generation should populate configs",
			existingDoc: &capabilities.Document{
				Catalogers: []capabilities.CatalogerEntry{},
			},
			newConfigs: map[string]capabilities.CatalogerConfigEntry{
				"python.CatalogerConfig": {
					Fields: []capabilities.CatalogerConfigFieldEntry{
						{Key: "GuessUnpinnedRequirements", Description: "guess unpinned reqs", AppKey: "python.guess-unpinned-requirements"},
					},
				},
			},
			newAppConfigs: []capabilities.ApplicationConfigField{
				{Key: "python.guess-unpinned-requirements", Description: "Guess unpinned requirements", DefaultValue: false},
			},
			expectedConfigs: map[string]capabilities.CatalogerConfigEntry{
				"python.CatalogerConfig": {
					Fields: []capabilities.CatalogerConfigFieldEntry{
						{Key: "GuessUnpinnedRequirements", Description: "guess unpinned reqs", AppKey: "python.guess-unpinned-requirements"},
					},
				},
			},
			expectedAppConfigs: []capabilities.ApplicationConfigField{
				{Key: "python.guess-unpinned-requirements", Description: "Guess unpinned requirements", DefaultValue: false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// use mergeDiscoveredWithExisting to properly test the integration
			updated, _, _ := mergeDiscoveredWithExisting(
				map[string]DiscoveredCataloger{},
				map[string][]string{},
				map[string][]string{},
				[]binary.Classifier{},
				[]capabilities.CatalogerInfo{},
				tt.existingDoc,
				tt.newConfigs,
				tt.newAppConfigs,
				map[string]string{},
			)

			// verify configs were replaced (not merged)
			if diff := cmp.Diff(tt.expectedConfigs, updated.Configs); diff != "" {
				t.Errorf("Configs mismatch (-want +got):\n%s", diff)
			}

			// verify app-configs were replaced (not merged)
			if diff := cmp.Diff(tt.expectedAppConfigs, updated.ApplicationConfig); diff != "" {
				t.Errorf("ApplicationConfig mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMergeCatalogerConfigField(t *testing.T) {
	tests := []struct {
		name                    string
		existingEntry           capabilities.CatalogerEntry
		discoveredInfo          DiscoveredCataloger
		catalogerConfigMappings map[string]string
		expectedConfig          string
	}{
		{
			name: "config field is updated from discovered data",
			existingEntry: capabilities.CatalogerEntry{
				Name:   "go-module-binary-cataloger",
				Config: "", // was empty
			},
			discoveredInfo: DiscoveredCataloger{
				Name: "go-module-binary-cataloger",
				Type: "generic",
			},
			catalogerConfigMappings: map[string]string{
				"go-module-binary-cataloger": "golang.CatalogerConfig",
			},
			expectedConfig: "golang.CatalogerConfig",
		},
		{
			name: "config field is replaced if different",
			existingEntry: capabilities.CatalogerEntry{
				Name:   "go-module-binary-cataloger",
				Config: "golang.OldConfig",
			},
			discoveredInfo: DiscoveredCataloger{
				Name: "go-module-binary-cataloger",
				Type: "generic",
			},
			catalogerConfigMappings: map[string]string{
				"go-module-binary-cataloger": "golang.NewConfig",
			},
			expectedConfig: "golang.NewConfig",
		},
		{
			name: "config field is cleared if no mapping exists",
			existingEntry: capabilities.CatalogerEntry{
				Name:   "go-module-binary-cataloger",
				Config: "golang.OldConfig",
			},
			discoveredInfo: DiscoveredCataloger{
				Name: "go-module-binary-cataloger",
				Type: "generic",
			},
			catalogerConfigMappings: map[string]string{},
			expectedConfig:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// simulate updateEntry which should update the Config field
			updated, _, _ := updateEntry(&tt.existingEntry, tt.discoveredInfo, nil, tt.catalogerConfigMappings)

			require.Equal(t, tt.expectedConfig, updated.Config)
		})
	}
}

func TestMergePreservesManualCapabilities(t *testing.T) {
	// ensure that while we update configs (AUTO-GENERATED),
	// we still preserve capabilities (MANUAL)
	existingDoc := &capabilities.Document{
		Configs: map[string]capabilities.CatalogerConfigEntry{
			"golang.OldConfig": {
				Fields: []capabilities.CatalogerConfigFieldEntry{
					{Key: "OldField", Description: "old"},
				},
			},
		},
		Catalogers: []capabilities.CatalogerEntry{
			{
				Name: "test-cataloger",
				Type: "generic",
				Parsers: []capabilities.Parser{
					{
						ParserFunction: "parseTest",
						Capabilities: capabilities.CapabilitySet{
							{Name: "license", Default: true}, // manual value
						},
					},
				},
			},
		},
	}

	discovered := map[string]DiscoveredCataloger{
		"test-cataloger": {
			Name: "test-cataloger",
			Type: "generic",
			Parsers: []DiscoveredParser{
				{
					ParserFunction: "parseTest",
					Method:         "glob",
					Criteria:       []string{"**/*.test"},
				},
			},
		},
	}

	newConfigs := map[string]capabilities.CatalogerConfigEntry{
		"golang.NewConfig": {
			Fields: []capabilities.CatalogerConfigFieldEntry{
				{Key: "NewField", Description: "new"},
			},
		},
	}

	updated, _, _ := mergeDiscoveredWithExisting(
		discovered,
		map[string][]string{},
		map[string][]string{},
		[]binary.Classifier{},
		[]capabilities.CatalogerInfo{
			{Name: "test-cataloger", Selectors: []string{"test"}},
		},
		existingDoc,
		newConfigs,
		[]capabilities.ApplicationConfigField{},
		map[string]string{},
	)

	// verify configs were replaced
	require.Len(t, updated.Configs, 1)
	_, hasOld := updated.Configs["golang.OldConfig"]
	require.False(t, hasOld, "old config should be removed")
	_, hasNew := updated.Configs["golang.NewConfig"]
	require.True(t, hasNew, "new config should be present")

	// verify capabilities were preserved
	require.Len(t, updated.Catalogers, 1)
	require.Len(t, updated.Catalogers[0].Parsers, 1)
	parser := updated.Catalogers[0].Parsers[0]
	require.Len(t, parser.Capabilities, 1)
	require.Equal(t, "license", parser.Capabilities[0].Name, "manual capability field should be preserved")
	require.Equal(t, true, parser.Capabilities[0].Default, "manual capability value should be preserved")

	// verify AUTO-GENERATED parser fields were updated
	require.Equal(t, "glob", string(parser.Detector.Method))
	require.Equal(t, []string{"**/*.test"}, parser.Detector.Criteria)
}

func TestCatalogerConfigFieldUpdatedForNewCatalogers(t *testing.T) {
	tests := []struct {
		name                    string
		catalogerName           string
		catalogerType           string
		catalogerConfigMappings map[string]string
		expectedConfig          string
	}{
		{
			name:          "new generic cataloger gets config from mapping",
			catalogerName: "go-module-binary-cataloger",
			catalogerType: "generic",
			catalogerConfigMappings: map[string]string{
				"go-module-binary-cataloger": "golang.CatalogerConfig",
			},
			expectedConfig: "golang.CatalogerConfig",
		},
		{
			name:          "new custom cataloger gets config from mapping",
			catalogerName: "java-archive-cataloger",
			catalogerType: "custom",
			catalogerConfigMappings: map[string]string{
				"java-archive-cataloger": "java.CatalogerConfig",
			},
			expectedConfig: "java.CatalogerConfig",
		},
		{
			name:                    "new cataloger without mapping has empty config",
			catalogerName:           "python-cataloger",
			catalogerType:           "generic",
			catalogerConfigMappings: map[string]string{},
			expectedConfig:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// test for generic catalogers
			if tt.catalogerType == "generic" {
				discovered := map[string]DiscoveredCataloger{
					tt.catalogerName: {
						Name: tt.catalogerName,
						Type: "generic",
						Parsers: []DiscoveredParser{
							{
								ParserFunction: "parseTest",
								Method:         "glob",
								Criteria:       []string{"**/*.test"},
							},
						},
					},
				}

				updated, _, _ := mergeDiscoveredWithExisting(
					discovered,
					map[string][]string{},
					map[string][]string{},
					[]binary.Classifier{},
					[]capabilities.CatalogerInfo{
						{Name: tt.catalogerName, Selectors: []string{"test"}},
					},
					&capabilities.Document{Catalogers: []capabilities.CatalogerEntry{}},
					map[string]capabilities.CatalogerConfigEntry{},
					[]capabilities.ApplicationConfigField{},
					tt.catalogerConfigMappings,
				)

				require.Len(t, updated.Catalogers, 1)
				require.Equal(t, tt.expectedConfig, updated.Catalogers[0].Config)
			}

			// test for custom catalogers
			if tt.catalogerType == "custom" {
				updated, _, _ := mergeDiscoveredWithExisting(
					map[string]DiscoveredCataloger{},
					map[string][]string{},
					map[string][]string{},
					[]binary.Classifier{},
					[]capabilities.CatalogerInfo{
						{Name: tt.catalogerName, Selectors: []string{"test"}},
					},
					&capabilities.Document{Catalogers: []capabilities.CatalogerEntry{}},
					map[string]capabilities.CatalogerConfigEntry{},
					[]capabilities.ApplicationConfigField{},
					tt.catalogerConfigMappings,
				)

				require.Len(t, updated.Catalogers, 1)
				require.Equal(t, tt.expectedConfig, updated.Catalogers[0].Config)
			}
		})
	}
}
