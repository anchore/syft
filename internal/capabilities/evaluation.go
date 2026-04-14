package capabilities

import "reflect"

// EvaluateCapabilities evaluates a capability set against a given configuration
// and returns the effective capability values as a flat map.
// Example: {"license": false, "dependency.depth": ["direct", "indirect"]}
func EvaluateCapabilities(caps CapabilitySet, config map[string]any) map[string]any {
	result := make(map[string]any)
	for _, capField := range caps {
		result[capField.Name] = EvaluateField(capField, config)
	}
	return result
}

// EvaluateField evaluates a single capability field against a configuration.
// Conditions are evaluated in order, and the first matching condition's value is returned.
// If no conditions match, the default value is returned.
func EvaluateField(capField CapabilityField, config map[string]any) any {
	// check conditions in order (first match wins)
	for _, cond := range capField.Conditions {
		if ConditionMatches(cond.When, config) {
			return cond.Value
		}
	}
	// no condition matched, return default
	return capField.Default
}

// ConditionMatches checks if a condition's when clause matches the given configuration.
// All fields in the when clause must match the config (AND logic).
// Returns true if all key-value pairs in when match the config.
func ConditionMatches(when map[string]any, config map[string]any) bool {
	// all fields in when must match config (AND logic)
	for key, expectedValue := range when {
		actualValue, exists := config[key]
		if !exists {
			return false
		}
		if !valuesEqual(actualValue, expectedValue) {
			return false
		}
	}
	return true
}

// valuesEqual compares two values for equality, handling different types appropriately.
// Uses reflect.DeepEqual for complex types like slices and maps.
func valuesEqual(a, b any) bool {
	// handle nil cases
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	// use reflect.DeepEqual for reliable comparison across types
	return reflect.DeepEqual(a, b)
}
