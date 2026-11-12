package perl

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// yaml.v3 does not honor json.Unmarshaler, so the lenient types that already tolerate both license and
// version shapes in JSON need their own UnmarshalYAML or a spec 1.4 META.yml fails on one field.
func Test_cpanMeta_lenientFieldsInYAML(t *testing.T) {
	tests := []struct {
		name            string
		contents        string
		expectedVersion scalar
		expectedLicense stringList
	}{
		{
			// what a real ExtUtils::MakeMaker 6.x META.yml writes: version unquoted, license a bare string
			name:            "spec 1.4 shapes",
			contents:        "name: Text-CSV\nversion: 1.21\nlicense: perl\n",
			expectedVersion: "1.21",
			expectedLicense: stringList{"perl"},
		},
		{
			name:            "quoted version and a license list",
			contents:        "name: URI\nversion: '5.35'\nlicense:\n  - perl_5\n  - artistic_2\n",
			expectedVersion: "5.35",
			expectedLicense: stringList{"perl_5", "artistic_2"},
		},
		{
			// a version that would read as a v-string rather than a number
			name:            "v-string version",
			contents:        "name: App-cpm\nversion: v1.1.4\n",
			expectedVersion: "v1.1.4",
		},
		{
			name:            "explicit nulls",
			contents:        "name: Foo\nversion: ~\nlicense: ~\n",
			expectedVersion: "",
			expectedLicense: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m cpanMeta
			require.NoError(t, yaml.Unmarshal([]byte(tt.contents), &m))
			assert.Equal(t, tt.expectedVersion, m.Version)
			assert.Equal(t, tt.expectedLicense, m.License)
		})
	}
}

func Test_cpanMeta_licenseExpressions(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		expected []string
	}{
		{
			// an SPDX expression is what syft's license parsing understands directly, where perl_5 is a
			// CPAN::Meta token that has to be translated
			name:     "x_spdx_expression wins",
			contents: `{"license":["perl_5"],"x_spdx_expression":"Artistic-1.0-Perl OR GPL-1.0-or-later"}`,
			expected: []string{"Artistic-1.0-Perl OR GPL-1.0-or-later"},
		},
		{
			name:     "license is used when there is no expression",
			contents: `{"license":["perl_5"]}`,
			expected: []string{"perl_5"},
		},
		{
			name:     "single-string license, as spec 1.4 writes it",
			contents: `{"license":"perl"}`,
			expected: []string{"perl"},
		},
		{
			name:     "neither present",
			contents: `{"name":"Foo"}`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m cpanMeta
			require.NoError(t, json.Unmarshal([]byte(tt.contents), &m))
			assert.Equal(t, tt.expected, m.licenseExpressions())
		})
	}
}

func Test_cpanMeta_prereqModules(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		expected []string
	}{
		{
			name: "spec 2 prereqs, keyed by phase",
			contents: `{"prereqs":{
				"runtime": {"requires": {"MIME::Base64": "2.1"}},
				"build":   {"requires": {"ExtUtils::MakeMaker": "0"}},
				"test":    {"requires": {"Test::More": "0.88"}},
				"develop": {"requires": {"Pod::Coverage": "0"}}
			}}`,
			expected: []string{"MIME::Base64", "ExtUtils::MakeMaker"},
		},
		{
			// spec 1.4 has no phase nesting at all, so the two flat maps feed the same two buckets
			name:     "spec 1.4 flat requirements",
			contents: `{"requires":{"IO::Handle":"0"},"build_requires":{"Test::More":"0.47"}}`,
			expected: []string{"IO::Handle", "Test::More"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m cpanMeta
			require.NoError(t, json.Unmarshal([]byte(tt.contents), &m))
			assert.ElementsMatch(t, tt.expected, m.prereqModules())
		})
	}
}
