package exp

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/capabilities"
)

func TestPackageCatalogerCapabilities(t *testing.T) {
	first, err := PackageCatalogerCapabilities()
	require.NoError(t, err)
	require.Greater(t, len(first), 10)

	second, err := PackageCatalogerCapabilities()
	require.NoError(t, err)
	require.Equal(t, len(first), len(second))

	names := make([]string, 0, len(first))
	for _, entry := range first {
		names = append(names, entry.Name)
	}
	assert.True(t, sort.StringsAreSorted(names))

	pythonIndex := -1
	for index, entry := range first {
		if entry.Name == "python-package-cataloger" {
			pythonIndex = index
			break
		}
	}
	require.NotEqual(t, -1, pythonIndex)
	require.NotEmpty(t, first[pythonIndex].Selectors)
	require.NotEmpty(t, first[pythonIndex].Parsers)
	assert.NotEmpty(t, first[pythonIndex].Parsers[0].Detector.Criteria)

	wantSelector := second[pythonIndex].Selectors[0]
	first[pythonIndex].Selectors[0] = "changed"
	assert.Equal(t, wantSelector, second[pythonIndex].Selectors[0])
}

func TestToCapabilitiesCopiesAllFields(t *testing.T) {
	entry := capabilities.CatalogerEntry{
		Ecosystem: "test-ecosystem",
		Name:      "test-cataloger",
		Type:      "generic",
		Source: capabilities.Source{
			File:     "some/file.go",
			Function: "NewCataloger",
		},
		Config:    "test.Config",
		Selectors: []string{"test", "package"},
		Parsers: []capabilities.Parser{
			{
				ParserFunction: "parseThing",
				Detector: capabilities.Detector{
					Method:   capabilities.GlobDetection,
					Criteria: []string{"**/thing.lock"},
					Conditions: []capabilities.DetectorCondition{
						{When: map[string]any{"Enabled": true}, Comment: "condition comment"},
					},
					Packages: []capabilities.DetectorPackageInfo{
						{Class: "class", Name: "name", PURL: "pkg:generic/name", CPEs: []string{"cpe:/a:name"}, Type: "TestPkg"},
					},
					Comment: "detector comment",
				},
				MetadataTypes:   []string{"ThingMetadata"},
				PackageTypes:    []string{"thing"},
				PURLTypes:       []string{"generic"},
				JSONSchemaTypes: []string{"ThingMetadata"},
				Capabilities: capabilities.CapabilitySet{
					{
						Name:       "license",
						Default:    false,
						Conditions: []capabilities.CapabilityCondition{{When: map[string]any{"Enabled": true}, Value: true, Comment: "capability condition"}},
						Evidence:   []string{"file.go:12"},
						Comment:    "capability comment",
					},
				},
			},
		},
		Detectors:       []capabilities.Detector{{Method: capabilities.MIMETypeDetection, Criteria: []string{"application/x-test"}}},
		MetadataTypes:   []string{"TopMetadata"},
		PackageTypes:    []string{"top"},
		PURLTypes:       []string{"top-purl"},
		JSONSchemaTypes: []string{"TopMetadata"},
		Capabilities:    capabilities.CapabilitySet{{Name: "dependency.depth", Default: []any{"direct"}}},
	}

	got := toCapabilities(entry)

	assert.Equal(t, "test-ecosystem", got.Ecosystem)
	assert.Equal(t, "test-cataloger", got.Name)
	assert.Equal(t, "generic", got.Type)
	assert.Equal(t, Source{File: "some/file.go", Function: "NewCataloger"}, got.Source)
	assert.Equal(t, "test.Config", got.Config)
	assert.Equal(t, []string{"test", "package"}, got.Selectors)
	assert.Equal(t, []string{"TopMetadata"}, got.MetadataTypes)
	assert.Equal(t, []string{"top"}, got.PackageTypes)
	assert.Equal(t, []string{"top-purl"}, got.PURLTypes)
	assert.Equal(t, []string{"TopMetadata"}, got.JSONSchemaTypes)

	require.Len(t, got.Detectors, 1)
	assert.Equal(t, MIMETypeDetection, got.Detectors[0].Method)
	assert.Equal(t, []string{"application/x-test"}, got.Detectors[0].Criteria)

	require.Len(t, got.Parsers, 1)
	parser := got.Parsers[0]
	assert.Equal(t, "parseThing", parser.ParserFunction)
	assert.Equal(t, GlobDetection, parser.Detector.Method)
	assert.Equal(t, []string{"**/thing.lock"}, parser.Detector.Criteria)
	assert.Equal(t, "detector comment", parser.Detector.Comment)
	assert.Equal(t, []string{"ThingMetadata"}, parser.MetadataTypes)
	assert.Equal(t, []string{"thing"}, parser.PackageTypes)
	assert.Equal(t, []string{"generic"}, parser.PURLTypes)
	assert.Equal(t, []string{"ThingMetadata"}, parser.JSONSchemaTypes)

	require.Len(t, parser.Detector.Conditions, 1)
	assert.Equal(t, map[string]any{"Enabled": true}, parser.Detector.Conditions[0].When)
	assert.Equal(t, "condition comment", parser.Detector.Conditions[0].Comment)

	require.Len(t, parser.Detector.Packages, 1)
	assert.Equal(t, DetectorPackageInfo{
		Class: "class",
		Name:  "name",
		PURL:  "pkg:generic/name",
		CPEs:  []string{"cpe:/a:name"},
		Type:  "TestPkg",
	}, parser.Detector.Packages[0])

	require.Len(t, parser.Capabilities, 1)
	assert.Equal(t, "license", parser.Capabilities[0].Name)
	assert.Equal(t, false, parser.Capabilities[0].Default)
	assert.Equal(t, []string{"file.go:12"}, parser.Capabilities[0].Evidence)
	assert.Equal(t, "capability comment", parser.Capabilities[0].Comment)
	require.Len(t, parser.Capabilities[0].Conditions, 1)
	assert.Equal(t, true, parser.Capabilities[0].Conditions[0].Value)
	assert.Equal(t, "capability condition", parser.Capabilities[0].Conditions[0].Comment)

	require.Len(t, got.Capabilities, 1)
	assert.Equal(t, "dependency.depth", got.Capabilities[0].Name)
	assert.Equal(t, []any{"direct"}, got.Capabilities[0].Default)
}

func TestToCapabilitiesDoesNotShareMutableData(t *testing.T) {
	entry := capabilities.CatalogerEntry{
		Selectors: []string{"selector"},
		Detectors: []capabilities.Detector{
			{
				Criteria: []string{"**/file"},
				Conditions: []capabilities.DetectorCondition{
					{When: map[string]any{"nested": []any{map[string]any{"key": "value"}}}},
				},
			},
		},
		Capabilities: capabilities.CapabilitySet{
			{
				Default: []any{map[string]any{"key": "value"}},
				Conditions: []capabilities.CapabilityCondition{
					{
						When:  map[string]any{"values": []string{"one"}},
						Value: map[string]any{"items": []any{"one"}},
					},
				},
			},
		},
	}

	got := toCapabilities(entry)
	got.Selectors[0] = "changed"
	got.Detectors[0].Criteria[0] = "changed"
	got.Detectors[0].Conditions[0].When["nested"].([]any)[0].(map[string]any)["key"] = "changed"
	got.Capabilities[0].Default.([]any)[0].(map[string]any)["key"] = "changed"
	got.Capabilities[0].Conditions[0].When["values"].([]string)[0] = "changed"
	got.Capabilities[0].Conditions[0].Value.(map[string]any)["items"].([]any)[0] = "changed"

	assert.Equal(t, []string{"selector"}, entry.Selectors)
	assert.Equal(t, []string{"**/file"}, entry.Detectors[0].Criteria)
	assert.Equal(t, "value", entry.Detectors[0].Conditions[0].When["nested"].([]any)[0].(map[string]any)["key"])
	assert.Equal(t, "value", entry.Capabilities[0].Default.([]any)[0].(map[string]any)["key"])
	assert.Equal(t, "one", entry.Capabilities[0].Conditions[0].When["values"].([]string)[0])
	assert.Equal(t, "one", entry.Capabilities[0].Conditions[0].Value.(map[string]any)["items"].([]any)[0])
}
