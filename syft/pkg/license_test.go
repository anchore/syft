package pkg

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

func Test_Hash(t *testing.T) {
	ctx := context.TODO()
	loc1 := file.NewLocation("place!")
	loc1.FileSystemID = "fs1"
	loc2 := file.NewLocation("place!")
	loc2.FileSystemID = "fs2" // important! there is a different file system ID

	lic1 := NewLicenseFromFieldsWithContext(ctx, "MIT", "foo", &loc1)
	lic2 := NewLicenseFromFieldsWithContext(ctx, "MIT", "bar", &loc2)

	hash1, err := artifact.IDByHash(lic1)
	require.NoError(t, err)

	hash2, err := artifact.IDByHash(lic2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2)
}

func Test_Sort(t *testing.T) {
	ctx := context.TODO()
	tests := []struct {
		name     string
		licenses Licenses
		expected Licenses
	}{
		{
			name:     "empty",
			licenses: []License{},
			expected: []License{},
		},
		{
			name: "single",
			licenses: []License{
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("place!")),
			},
			expected: []License{
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("place!")),
			},
		},
		{
			name: "multiple",
			licenses: []License{
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("place!")),
				NewLicenseFromURLsWithContext(ctx, "MIT", "https://github.com/anchore/syft/blob/main/LICENSE"),
				NewLicenseFromLocationsWithContext(ctx, "Apache", file.NewLocation("area!")),
				NewLicenseFromLocationsWithContext(ctx, "gpl2+", file.NewLocation("area!")),
			},
			expected: Licenses{
				NewLicenseFromLocationsWithContext(ctx, "Apache", file.NewLocation("area!")),
				NewLicenseFromURLsWithContext(ctx, "MIT", "https://github.com/anchore/syft/blob/main/LICENSE"),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("place!")),
				NewLicenseFromLocationsWithContext(ctx, "gpl2+", file.NewLocation("area!")),
			},
		},
		{
			name: "multiple with location variants",
			licenses: []License{
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("place!")),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("park!")),
				NewLicenseWithContext(ctx, "MIT"),
				NewLicenseWithContext(ctx, "AAL"),
				NewLicenseWithContext(ctx, "Adobe-2006"),
				NewLicenseFromLocationsWithContext(ctx, "Apache", file.NewLocation("area!")),
			},
			expected: Licenses{
				NewLicenseWithContext(ctx, "AAL"),
				NewLicenseWithContext(ctx, "Adobe-2006"),
				NewLicenseFromLocationsWithContext(ctx, "Apache", file.NewLocation("area!")),
				NewLicenseWithContext(ctx, "MIT"),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("park!")),
				NewLicenseFromLocationsWithContext(ctx, "MIT", file.NewLocation("place!")),
			},
		},
		{
			name: "multiple licenses with only contents are still sorted by their computed lic.value references",
			licenses: []License{
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/nvidia-software-and-cuda-supplement")),
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/Knuth-CTAN")),
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/apache-license-2.0")),
			},
			expected: Licenses{
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/apache-license-2.0")),
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/nvidia-software-and-cuda-supplement")),
				NewLicenseWithContext(ctx, readFileAsString("../../internal/licenses/test-fixtures/Knuth-CTAN")),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sort.Sort(test.licenses)
			assert.Equal(t, test.expected, test.licenses)
		})

	}
}

func TestLicense_Merge(t *testing.T) {
	locA := file.NewLocation("a")
	locB := file.NewLocation("b")

	tests := []struct {
		name    string
		subject License
		other   License
		want    License
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "valid merge",
			subject: License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Declared,
				URLs: []string{
					"b", "a",
				},
				Locations: file.NewLocationSet(locA),
			},
			other: License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Declared,
				URLs: []string{
					"c", "d",
				},
				Locations: file.NewLocationSet(locB),
			},
			want: License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Declared,
				URLs: []string{
					"a", "b", "c", "d",
				},
				Locations: file.NewLocationSet(locA, locB),
			},
		},
		{
			name: "mismatched value",
			subject: License{
				Value:          "DIFFERENT!!",
				SPDXExpression: "MIT",
				Type:           license.Declared,
				URLs: []string{
					"b", "a",
				},
				Locations: file.NewLocationSet(locA),
			},
			other: License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Declared,
				URLs: []string{
					"c", "d",
				},
				Locations: file.NewLocationSet(locB),
			},
			wantErr: require.Error,
		},
		{
			name: "mismatched spdx expression",
			subject: License{
				Value:          "MIT",
				SPDXExpression: "DIFFERENT!!",
				Type:           license.Declared,
				URLs: []string{
					"b", "a",
				},
				Locations: file.NewLocationSet(locA),
			},
			other: License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Declared,
				URLs: []string{
					"c", "d",
				},
				Locations: file.NewLocationSet(locB),
			},
			wantErr: require.Error,
		},
		{
			name: "mismatched type",
			subject: License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Concluded,
				URLs: []string{
					"b", "a",
				},
				Locations: file.NewLocationSet(locA),
			},
			other: License{
				Value:          "MIT",
				SPDXExpression: "MIT",
				Type:           license.Declared,
				URLs: []string{
					"c", "d",
				},
				Locations: file.NewLocationSet(locB),
			},
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			subjectLocationLen := len(tt.subject.Locations.ToSlice())
			subjectURLLen := len(tt.subject.URLs)

			got, err := tt.subject.Merge(tt.other)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			require.NotNilf(t, got, "expected a non-nil license")
			assert.Equal(t, tt.want, *got)
			// prove we don't modify the subject
			assert.Equal(t, subjectLocationLen, len(tt.subject.Locations.ToSlice()))
			assert.Equal(t, subjectURLLen, len(tt.subject.URLs))
		})
	}
}

func TestFullText(t *testing.T) {
	ctx := context.TODO()
	fullText := `I am a license with full text
	my authors put new line characters in metadata for labeling a license`
	tests := []struct {
		name  string
		value string
		want  License
	}{
		{
			name:  "Full Text field is populated with the correct full text and contents are given a sha256 as value",
			value: fullText,
			want: License{
				Value:    "sha256:108067fa71229a2b98b9696af0ce21cd11d9639634c8bc94bda70ebedf291e5a",
				Type:     license.Declared,
				Contents: fullText,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewLicenseWithContext(ctx, tt.value)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLicenseConstructors(t *testing.T) {
	ctx := context.TODO()
	type input struct {
		value string
		urls  []string
	}
	tests := []struct {
		name     string
		input    input
		expected License
	}{
		{
			name: "License URLs are stripped of newlines and tabs",
			input: input{
				value: "New BSD License",
				urls: []string{
					`
						http://user-agent-utils.googlecode.com/svn/trunk/UserAgentUtils/LICENSE.txt
					`},
			},
			expected: License{
				Value: "New BSD License",
				Type:  license.Declared,
				URLs:  []string{"http://user-agent-utils.googlecode.com/svn/trunk/UserAgentUtils/LICENSE.txt"},
			},
		},
		{
			name: "License URLs without value",
			input: input{
				value: "",
				urls:  []string{"http://user-agent-utils.googlecode.com/svn/trunk/UserAgentUtils/LICENSE.txt"},
			},
			expected: License{
				Type: license.Declared,
				URLs: []string{"http://user-agent-utils.googlecode.com/svn/trunk/UserAgentUtils/LICENSE.txt"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := NewLicenseFromURLsWithContext(ctx, test.input.value, test.input.urls...)
			assert.Equal(t, test.expected, got)
		})
	}
}
