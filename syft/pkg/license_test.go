package pkg

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/source"
)

func Test_Hash(t *testing.T) {

	loc1 := source.NewLocation("place!")
	loc1.FileSystemID = "fs1"
	loc2 := source.NewLocation("place!")
	loc2.FileSystemID = "fs2" // important! there is a different file system ID

	lic1 := NewLicenseFromLocation("MIT", loc1)
	lic2 := NewLicenseFromLocation("MIT", loc2)

	hash1, err := artifact.IDByHash(lic1)
	require.NoError(t, err)

	hash2, err := artifact.IDByHash(lic2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2)
}

func Test_Sort(t *testing.T) {
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
				NewLicenseFromLocation("MIT", source.NewLocation("place!")),
			},
			expected: []License{
				NewLicenseFromLocation("MIT", source.NewLocation("place!")),
			},
		},
		{
			name: "multiple",
			licenses: []License{
				NewLicenseFromLocation("MIT", source.NewLocation("place!")),
				NewLicenseFromURL("MIT", "https://github.com/anchore/syft/blob/main/LICENSE"),
				NewLicenseFromLocation("Apache", source.NewLocation("area!")),
				NewLicenseFromLocation("gpl2+", source.NewLocation("area!")),
			},
			expected: Licenses{
				NewLicenseFromLocation("Apache", source.NewLocation("area!")),
				NewLicenseFromLocation("MIT", source.NewLocation("place!")),
				NewLicenseFromURL("MIT", "https://github.com/anchore/syft/blob/main/LICENSE"),
				NewLicenseFromLocation("gpl2+", source.NewLocation("area!")),
			},
		},
		{
			name: "multiple with location variants",
			licenses: []License{
				NewLicenseFromLocation("MIT", source.NewLocation("place!")),
				NewLicenseFromLocation("MIT", source.NewLocation("park!")),
				NewLicense("MIT"),
				NewLicense("AAL"),
				NewLicense("Adobe-2006"),
				NewLicenseFromLocation("Apache", source.NewLocation("area!")),
			},
			expected: Licenses{
				NewLicense("AAL"),
				NewLicense("Adobe-2006"),
				NewLicenseFromLocation("Apache", source.NewLocation("area!")),
				NewLicense("MIT"),
				NewLicenseFromLocation("MIT", source.NewLocation("park!")),
				NewLicenseFromLocation("MIT", source.NewLocation("place!")),
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
