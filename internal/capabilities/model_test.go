package capabilities

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConfigSchemaExtensions(t *testing.T) {
	// create a document with configs and app-configs
	doc := Document{
		Configs: map[string]CatalogerConfigEntry{
			"golang.CatalogerConfig": {
				Fields: []CatalogerConfigFieldEntry{
					{
						Key:         "SearchLocalModCacheLicenses",
						Description: "searchLocalModCacheLicenses enables searching for go package licenses in the local GOPATH mod cache.",
						AppKey:      "golang.search-local-mod-cache-licenses",
					},
					{
						Key:         "LocalModCacheDir",
						Description: "localModCacheDir specifies the location of the local go module cache directory.",
						AppKey:      "golang.local-mod-cache-dir",
					},
				},
			},
			"python.CatalogerConfig": {
				Fields: []CatalogerConfigFieldEntry{
					{
						Key:         "GuessUnpinnedRequirements",
						Description: "guessUnpinnedRequirements attempts to infer package versions from version constraints...",
						AppKey:      "python.guess-unpinned-requirements",
					},
				},
			},
		},
		ApplicationConfig: []ApplicationConfigField{
			{
				Key:          "golang.search-local-mod-cache-licenses",
				Description:  "search for go package licences in the GOPATH of the system running Syft",
				DefaultValue: false,
			},
			{
				Key:          "python.guess-unpinned-requirements",
				Description:  "attempt to guess what the version could be based on version requirements",
				DefaultValue: false,
			},
		},
		Catalogers: []CatalogerEntry{
			{
				Name:   "go-module-binary-cataloger",
				Type:   "generic",
				Config: "golang.CatalogerConfig",
			},
			{
				Name:   "python-package-cataloger",
				Type:   "generic",
				Config: "python.CatalogerConfig",
			},
		},
	}

	// marshal to YAML
	yamlData, err := yaml.Marshal(&doc)
	require.NoError(t, err)

	// verify YAML contains expected sections
	yamlStr := string(yamlData)
	require.Contains(t, yamlStr, "configs:")
	require.Contains(t, yamlStr, "golang.CatalogerConfig:")
	require.Contains(t, yamlStr, "SearchLocalModCacheLicenses")
	require.Contains(t, yamlStr, "application:")
	require.Contains(t, yamlStr, "golang.search-local-mod-cache-licenses")

	// unmarshal back
	var unmarshaled Document
	err = yaml.Unmarshal(yamlData, &unmarshaled)
	require.NoError(t, err)

	// verify data integrity
	if diff := cmp.Diff(doc, unmarshaled); diff != "" {
		t.Errorf("document mismatch (-want +got):\n%s", diff)
	}
}

func TestConfigSchemaOmitEmpty(t *testing.T) {
	// create a document with no configs or app-configs
	doc := Document{
		Catalogers: []CatalogerEntry{
			{
				Name: "test-cataloger",
				Type: "generic",
			},
		},
	}

	// marshal to YAML
	yamlData, err := yaml.Marshal(&doc)
	require.NoError(t, err)

	// verify configs and application are omitted when empty
	yamlStr := string(yamlData)
	require.NotContains(t, yamlStr, "configs:")
	require.NotContains(t, yamlStr, "application:")
}

func TestCatalogerConfigField(t *testing.T) {
	// create a cataloger with config field
	entry := CatalogerEntry{
		Name:   "test-cataloger",
		Type:   "generic",
		Config: "test.CatalogerConfig",
	}

	// marshal to YAML
	yamlData, err := yaml.Marshal(&entry)
	require.NoError(t, err)

	// verify config field is present
	yamlStr := string(yamlData)
	require.Contains(t, yamlStr, "config: test.CatalogerConfig")

	// unmarshal back
	var unmarshaled CatalogerEntry
	err = yaml.Unmarshal(yamlData, &unmarshaled)
	require.NoError(t, err)

	// verify data integrity
	require.Equal(t, entry.Config, unmarshaled.Config)
}

func TestCatalogerConfigFieldOmitEmpty(t *testing.T) {
	// create a cataloger without config field
	entry := CatalogerEntry{
		Name: "test-cataloger",
		Type: "generic",
	}

	// marshal to YAML
	yamlData, err := yaml.Marshal(&entry)
	require.NoError(t, err)

	// verify config field is omitted when empty
	yamlStr := string(yamlData)
	require.NotContains(t, yamlStr, "config:")
}
