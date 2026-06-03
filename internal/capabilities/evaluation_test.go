package capabilities

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func Test_valuesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    any
		b    any
		want bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "first nil second non-nil",
			a:    nil,
			b:    "value",
			want: false,
		},
		{
			name: "first non-nil second nil",
			a:    "value",
			b:    nil,
			want: false,
		},
		{
			name: "equal strings",
			a:    "hello",
			b:    "hello",
			want: true,
		},
		{
			name: "different strings",
			a:    "hello",
			b:    "world",
			want: false,
		},
		{
			name: "equal booleans true",
			a:    true,
			b:    true,
			want: true,
		},
		{
			name: "equal booleans false",
			a:    false,
			b:    false,
			want: true,
		},
		{
			name: "different booleans",
			a:    true,
			b:    false,
			want: false,
		},
		{
			name: "equal integers",
			a:    42,
			b:    42,
			want: true,
		},
		{
			name: "different integers",
			a:    42,
			b:    43,
			want: false,
		},
		{
			name: "equal slices",
			a:    []string{"a", "b", "c"},
			b:    []string{"a", "b", "c"},
			want: true,
		},
		{
			name: "different slices",
			a:    []string{"a", "b", "c"},
			b:    []string{"a", "b", "d"},
			want: false,
		},
		{
			name: "slices different length",
			a:    []string{"a", "b"},
			b:    []string{"a", "b", "c"},
			want: false,
		},
		{
			name: "equal maps",
			a:    map[string]int{"x": 1, "y": 2},
			b:    map[string]int{"x": 1, "y": 2},
			want: true,
		},
		{
			name: "different maps",
			a:    map[string]int{"x": 1, "y": 2},
			b:    map[string]int{"x": 1, "y": 3},
			want: false,
		},
		{
			name: "different types string vs int",
			a:    "42",
			b:    42,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valuesEqual(tt.a, tt.b)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConditionMatches(t *testing.T) {
	tests := []struct {
		name   string
		when   map[string]any
		config map[string]any
		want   bool
	}{
		{
			name:   "empty when clause matches anything",
			when:   map[string]any{},
			config: map[string]any{"key": "value"},
			want:   true,
		},
		{
			name:   "empty when clause with empty config",
			when:   map[string]any{},
			config: map[string]any{},
			want:   true,
		},
		{
			name:   "single key match",
			when:   map[string]any{"SearchLocalModCacheLicenses": true},
			config: map[string]any{"SearchLocalModCacheLicenses": true},
			want:   true,
		},
		{
			name:   "single key mismatch",
			when:   map[string]any{"SearchLocalModCacheLicenses": true},
			config: map[string]any{"SearchLocalModCacheLicenses": false},
			want:   false,
		},
		{
			name:   "key missing from config",
			when:   map[string]any{"SearchLocalModCacheLicenses": true},
			config: map[string]any{},
			want:   false,
		},
		{
			name: "multiple keys all match",
			when: map[string]any{
				"SearchLocalModCacheLicenses": true,
				"UseNetwork":                  true,
			},
			config: map[string]any{
				"SearchLocalModCacheLicenses": true,
				"UseNetwork":                  true,
				"ExtraKey":                    "ignored",
			},
			want: true,
		},
		{
			name: "multiple keys one mismatch",
			when: map[string]any{
				"SearchLocalModCacheLicenses": true,
				"UseNetwork":                  true,
			},
			config: map[string]any{
				"SearchLocalModCacheLicenses": true,
				"UseNetwork":                  false,
			},
			want: false,
		},
		{
			name: "multiple keys one missing",
			when: map[string]any{
				"SearchLocalModCacheLicenses": true,
				"UseNetwork":                  true,
			},
			config: map[string]any{
				"SearchLocalModCacheLicenses": true,
			},
			want: false,
		},
		{
			name:   "string value match",
			when:   map[string]any{"mode": "fast"},
			config: map[string]any{"mode": "fast"},
			want:   true,
		},
		{
			name:   "slice value match",
			when:   map[string]any{"formats": []string{"json", "yaml"}},
			config: map[string]any{"formats": []string{"json", "yaml"}},
			want:   true,
		},
		{
			name:   "slice value mismatch",
			when:   map[string]any{"formats": []string{"json", "yaml"}},
			config: map[string]any{"formats": []string{"json", "xml"}},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConditionMatches(tt.when, tt.config)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEvaluateField(t *testing.T) {
	tests := []struct {
		name     string
		capField CapabilityField
		config   map[string]any
		want     any
	}{
		{
			name: "no conditions returns default",
			capField: CapabilityField{
				Name:       "license",
				Default:    false,
				Conditions: nil,
			},
			config: map[string]any{},
			want:   false,
		},
		{
			name: "empty conditions returns default",
			capField: CapabilityField{
				Name:       "license",
				Default:    false,
				Conditions: []CapabilityCondition{},
			},
			config: map[string]any{},
			want:   false,
		},
		{
			name: "single condition matches",
			capField: CapabilityField{
				Name:    "license",
				Default: false,
				Conditions: []CapabilityCondition{
					{
						When:  map[string]any{"SearchLocalModCacheLicenses": true},
						Value: true,
					},
				},
			},
			config: map[string]any{"SearchLocalModCacheLicenses": true},
			want:   true,
		},
		{
			name: "single condition does not match",
			capField: CapabilityField{
				Name:    "license",
				Default: false,
				Conditions: []CapabilityCondition{
					{
						When:  map[string]any{"SearchLocalModCacheLicenses": true},
						Value: true,
					},
				},
			},
			config: map[string]any{"SearchLocalModCacheLicenses": false},
			want:   false,
		},
		{
			name: "multiple conditions first match wins",
			capField: CapabilityField{
				Name:    "license",
				Default: false,
				Conditions: []CapabilityCondition{
					{
						When:  map[string]any{"SearchLocalModCacheLicenses": true},
						Value: "local",
					},
					{
						When:  map[string]any{"SearchRemoteLicenses": true},
						Value: "remote",
					},
				},
			},
			config: map[string]any{
				"SearchLocalModCacheLicenses": true,
				"SearchRemoteLicenses":        true,
			},
			want: "local",
		},
		{
			name: "multiple conditions second matches",
			capField: CapabilityField{
				Name:    "license",
				Default: false,
				Conditions: []CapabilityCondition{
					{
						When:  map[string]any{"SearchLocalModCacheLicenses": true},
						Value: "local",
					},
					{
						When:  map[string]any{"SearchRemoteLicenses": true},
						Value: "remote",
					},
				},
			},
			config: map[string]any{
				"SearchLocalModCacheLicenses": false,
				"SearchRemoteLicenses":        true,
			},
			want: "remote",
		},
		{
			name: "no conditions match returns default",
			capField: CapabilityField{
				Name:    "license",
				Default: "none",
				Conditions: []CapabilityCondition{
					{
						When:  map[string]any{"SearchLocalModCacheLicenses": true},
						Value: "local",
					},
					{
						When:  map[string]any{"SearchRemoteLicenses": true},
						Value: "remote",
					},
				},
			},
			config: map[string]any{
				"SearchLocalModCacheLicenses": false,
				"SearchRemoteLicenses":        false,
			},
			want: "none",
		},
		{
			name: "slice default value",
			capField: CapabilityField{
				Name:       "dependency.depth",
				Default:    []string{"direct", "indirect"},
				Conditions: nil,
			},
			config: map[string]any{},
			want:   []string{"direct", "indirect"},
		},
		{
			name: "condition with multiple when keys",
			capField: CapabilityField{
				Name:    "feature",
				Default: false,
				Conditions: []CapabilityCondition{
					{
						When: map[string]any{
							"EnableFeatureA": true,
							"EnableFeatureB": true,
						},
						Value: true,
					},
				},
			},
			config: map[string]any{
				"EnableFeatureA": true,
				"EnableFeatureB": true,
			},
			want: true,
		},
		{
			name: "condition with multiple when keys partial match fails",
			capField: CapabilityField{
				Name:    "feature",
				Default: false,
				Conditions: []CapabilityCondition{
					{
						When: map[string]any{
							"EnableFeatureA": true,
							"EnableFeatureB": true,
						},
						Value: true,
					},
				},
			},
			config: map[string]any{
				"EnableFeatureA": true,
				"EnableFeatureB": false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateField(tt.capField, tt.config)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("EvaluateField() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEvaluateCapabilities(t *testing.T) {
	tests := []struct {
		name   string
		caps   CapabilitySet
		config map[string]any
		want   map[string]any
	}{
		{
			name:   "empty capability set",
			caps:   CapabilitySet{},
			config: map[string]any{},
			want:   map[string]any{},
		},
		{
			name: "single capability no conditions",
			caps: CapabilitySet{
				{
					Name:    "license",
					Default: false,
				},
			},
			config: map[string]any{},
			want: map[string]any{
				"license": false,
			},
		},
		{
			name: "single capability with matching condition",
			caps: CapabilitySet{
				{
					Name:    "license",
					Default: false,
					Conditions: []CapabilityCondition{
						{
							When:  map[string]any{"SearchLocalModCacheLicenses": true},
							Value: true,
						},
					},
				},
			},
			config: map[string]any{"SearchLocalModCacheLicenses": true},
			want: map[string]any{
				"license": true,
			},
		},
		{
			name: "multiple capabilities mixed conditions",
			caps: CapabilitySet{
				{
					Name:    "license",
					Default: false,
					Conditions: []CapabilityCondition{
						{
							When:  map[string]any{"SearchLocalModCacheLicenses": true},
							Value: true,
						},
					},
				},
				{
					Name:    "dependency.depth",
					Default: []string{"direct", "indirect"},
				},
				{
					Name:    "dependency.edges",
					Default: "flat",
				},
			},
			config: map[string]any{"SearchLocalModCacheLicenses": true},
			want: map[string]any{
				"license":          true,
				"dependency.depth": []string{"direct", "indirect"},
				"dependency.edges": "flat",
			},
		},
		{
			name: "real-world go module binary cataloger example",
			caps: CapabilitySet{
				{
					Name:    "license",
					Default: false,
					Conditions: []CapabilityCondition{
						{
							When:  map[string]any{"SearchLocalModCacheLicenses": true},
							Value: true,
						},
						{
							When:  map[string]any{"SearchRemoteLicenses": true},
							Value: true,
						},
					},
				},
				{
					Name:    "dependency.depth",
					Default: []string{"direct", "indirect"},
				},
				{
					Name:    "dependency.edges",
					Default: "flat",
				},
				{
					Name:    "package_manager.files.listing",
					Default: false,
				},
			},
			config: map[string]any{
				"SearchLocalModCacheLicenses": false,
				"SearchRemoteLicenses":        true,
			},
			want: map[string]any{
				"license":                       true,
				"dependency.depth":              []string{"direct", "indirect"},
				"dependency.edges":              "flat",
				"package_manager.files.listing": false,
			},
		},
		{
			name: "nil capability set",
			caps: nil,
			config: map[string]any{
				"anything": true,
			},
			want: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateCapabilities(tt.caps, tt.config)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("EvaluateCapabilities() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
