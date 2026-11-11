package rust

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCargoVersionRequirements(t *testing.T) {
	tests := []struct {
		requirement string
		accept      []string
		reject      []string
	}{
		{"1.2.3", []string{"1.2.3", "1.9.0"}, []string{"1.2.2", "2.0.0", "1.3.0-alpha"}},
		{"^0.2.3", []string{"0.2.3", "0.2.9"}, []string{"0.2.2", "0.3.0"}},
		{"^0.0.3", []string{"0.0.3"}, []string{"0.0.2", "0.0.4", "0.1.0"}},
		{"0.0", []string{"0.0.0", "0.0.9"}, []string{"0.1.0", "1.0.0"}},
		{"0", []string{"0.0.0", "0.9.9"}, []string{"1.0.0"}},
		{"~0.0.0", []string{"0.0.0", "0.0.9"}, []string{"0.1.0", "1.0.0"}},
		{"~1.2.3", []string{"1.2.3", "1.2.9"}, []string{"1.2.2", "1.3.0"}},
		{"~1.2", []string{"1.2.0", "1.2.9"}, []string{"1.1.9", "1.3.0"}},
		{"~1", []string{"1.0.0", "1.9.9"}, []string{"0.9.9", "2.0.0"}},
		{"*", []string{"0.0.0", "2.3.4"}, []string{"1.0.0-alpha"}},
		{"1.*", []string{"1.0.0", "1.9.9"}, []string{"0.9.9", "2.0.0", "1.0.0-alpha"}},
		{"1.2.*", []string{"1.2.0", "1.2.9"}, []string{"1.1.9", "1.3.0"}},
		{"=1.2.3", []string{"1.2.3", "1.2.3+metadata"}, []string{"1.2.2", "1.2.4", "1.2.3-alpha"}},
		{"=1.2", []string{"1.2.0", "1.2.9"}, []string{"1.3.0", "1.2.3-alpha"}},
		{">1.2", []string{"1.3.0", "2.0.0"}, []string{"1.2.0", "1.2.9"}},
		{">=1.2", []string{"1.2.0", "1.2.9", "2.0.0"}, []string{"1.1.9"}},
		{"<1.2", []string{"1.1.9", "0.9.9"}, []string{"1.2.0", "1.2.9"}},
		{"<=1.2", []string{"1.2.0", "1.2.9", "0.9.9"}, []string{"1.3.0"}},
		{">=1.2, <1.5", []string{"1.2.0", "1.4.9"}, []string{"1.1.9", "1.5.0"}},
		{"1.0.0-alpha", []string{"1.0.0-beta", "1.0.0", "1.9.0"}, []string{"0.9.9", "1.0.1-alpha", "1.1.0-alpha"}},
		{">=1.0.0-alpha, <2", []string{"1.0.0-beta", "1.9.0"}, []string{"1.1.0-alpha", "2.0.0-alpha", "2.0.0"}},
		{"^1.0, >=1.1.0-alpha", []string{"1.1.0-beta", "1.2.0"}, []string{"1.0.0", "1.2.0-alpha"}},
		{"~1.0, >=1.0.1-alpha", []string{"1.0.1"}, []string{"1.0.1-alpha", "1.1.0"}},
		{"=1.2.3+build", []string{"1.2.3", "1.2.3+other"}, []string{"1.2.4"}},
	}
	for _, tt := range tests {
		t.Run(tt.requirement, func(t *testing.T) {
			constraint, known := cargoVersionConstraint(tt.requirement)
			require.True(t, known)
			require.NotNil(t, constraint)
			for _, version := range tt.accept {
				parsed, err := semver.StrictNewVersion(version)
				require.NoError(t, err)
				assert.True(t, constraint.matches(parsed), "should accept %s", version)
			}
			for _, version := range tt.reject {
				parsed, err := semver.StrictNewVersion(version)
				require.NoError(t, err)
				assert.False(t, constraint.matches(parsed), "should reject %s", version)
			}
		})
	}
}

func TestCargoVersionRequirementUncertainSyntax(t *testing.T) {
	for _, input := range []string{"invalid", " ", "1 || 2", "01.2.3", "1.2.3.4", "1.2-alpha", "1,", "*.*", "1.*.2", ">1.*", "18446744073709551616.0.0"} {
		t.Run(input, func(t *testing.T) {
			_, known := cargoVersionConstraint(input)
			assert.False(t, known)
		})
	}
	constraint, known := cargoVersionConstraint("")
	assert.True(t, known)
	assert.Nil(t, constraint)
}
