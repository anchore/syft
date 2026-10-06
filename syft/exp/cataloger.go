package exp

import (
	"fmt"
	"slices"
	"sort"

	"github.com/anchore/syft/internal/capabilities"
	_ "github.com/anchore/syft/syft/pkg/cataloger"
)

// PackageCatalogerCapabilities returns capability information for all package catalogers.
func PackageCatalogerCapabilities() ([]Capabilities, error) {
	entries, err := capabilities.Packages()
	if err != nil {
		return nil, fmt.Errorf("unable to load package cataloger capabilities: %w", err)
	}

	result := make([]Capabilities, 0, len(entries))
	for _, entry := range entries {
		result = append(result, toCapabilities(entry))
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

func toCapabilities(entry capabilities.CatalogerEntry) Capabilities {
	return Capabilities{
		Ecosystem:       entry.Ecosystem,
		Name:            entry.Name,
		Type:            entry.Type,
		Source:          toSource(entry.Source),
		Config:          entry.Config,
		Selectors:       slices.Clone(entry.Selectors),
		Parsers:         convert(entry.Parsers, toParser),
		Detectors:       convert(entry.Detectors, toDetector),
		MetadataTypes:   slices.Clone(entry.MetadataTypes),
		PackageTypes:    slices.Clone(entry.PackageTypes),
		PURLTypes:       slices.Clone(entry.PURLTypes),
		JSONSchemaTypes: slices.Clone(entry.JSONSchemaTypes),
		Capabilities:    toCapabilitySet(entry.Capabilities),
	}
}

func toSource(source capabilities.Source) Source {
	return Source{
		File:     source.File,
		Function: source.Function,
	}
}

func toParser(parser capabilities.Parser) Parser {
	return Parser{
		ParserFunction:  parser.ParserFunction,
		Detector:        toDetector(parser.Detector),
		MetadataTypes:   slices.Clone(parser.MetadataTypes),
		PackageTypes:    slices.Clone(parser.PackageTypes),
		PURLTypes:       slices.Clone(parser.PURLTypes),
		JSONSchemaTypes: slices.Clone(parser.JSONSchemaTypes),
		Capabilities:    toCapabilitySet(parser.Capabilities),
	}
}

func toDetector(detector capabilities.Detector) Detector {
	return Detector{
		Method:     ArtifactDetectionMethod(detector.Method),
		Criteria:   slices.Clone(detector.Criteria),
		Conditions: convert(detector.Conditions, toDetectorCondition),
		Packages:   convert(detector.Packages, toDetectorPackageInfo),
		Comment:    detector.Comment,
	}
}

func toDetectorCondition(condition capabilities.DetectorCondition) DetectorCondition {
	return DetectorCondition{
		When:    cloneMap(condition.When),
		Comment: condition.Comment,
	}
}

func toDetectorPackageInfo(packageInfo capabilities.DetectorPackageInfo) DetectorPackageInfo {
	return DetectorPackageInfo{
		Class: packageInfo.Class,
		Name:  packageInfo.Name,
		PURL:  packageInfo.PURL,
		CPEs:  slices.Clone(packageInfo.CPEs),
		Type:  packageInfo.Type,
	}
}

func toCapabilitySet(set capabilities.CapabilitySet) CapabilitySet {
	return CapabilitySet(convert(set, toCapabilityField))
}

func toCapabilityField(field capabilities.CapabilityField) CapabilityField {
	return CapabilityField{
		Name:       field.Name,
		Default:    cloneValue(field.Default),
		Conditions: convert(field.Conditions, toCapabilityCondition),
		Evidence:   slices.Clone(field.Evidence),
		Comment:    field.Comment,
	}
}

func toCapabilityCondition(condition capabilities.CapabilityCondition) CapabilityCondition {
	return CapabilityCondition{
		When:    cloneMap(condition.When),
		Value:   cloneValue(condition.Value),
		Comment: condition.Comment,
	}
}

func convert[In any, Out any, Slice ~[]In](values Slice, convertValue func(In) Out) []Out {
	if values == nil {
		return nil
	}

	result := make([]Out, 0, len(values))
	for _, value := range values {
		result = append(result, convertValue(value))
	}
	return result
}

func cloneMap(values map[string]any) map[string]any {
	if values == nil {
		return nil
	}

	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	switch value := value.(type) {
	case []any:
		return convert(value, cloneValue)
	case []string:
		return slices.Clone(value)
	case map[string]any:
		return cloneMap(value)
	case map[any]any:
		result := make(map[any]any, len(value))
		for key, item := range value {
			result[key] = cloneValue(item)
		}
		return result
	default:
		return value
	}
}
