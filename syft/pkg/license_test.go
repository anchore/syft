package pkg

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
)

func Test_Hash(t *testing.T) {

	loc1 := file.NewLocation("place!")
	loc1.FileSystemID = "fs1"
	loc2 := file.NewLocation("place!")
	loc2.FileSystemID = "fs2" // important! there is a different file system ID

	lic1 := NewLicenseFromLocations("MIT", loc1)
	lic2 := NewLicenseFromLocations("MIT", loc2)

	lic1.URLs.Add("foo")
	lic2.URLs.Add("bar") // we also want to check the URLs are ignored

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
				NewLicenseFromLocations("MIT", file.NewLocation("place!")),
			},
			expected: []License{
				NewLicenseFromLocations("MIT", file.NewLocation("place!")),
			},
		},
		{
			name: "multiple",
			licenses: []License{
				NewLicenseFromLocations("MIT", file.NewLocation("place!")),
				NewLicenseFromURLs("MIT", "https://github.com/anchore/syft/blob/main/LICENSE"),
				NewLicenseFromLocations("Apache", file.NewLocation("area!")),
				NewLicenseFromLocations("gpl2+", file.NewLocation("area!")),
			},
			expected: Licenses{
				NewLicenseFromLocations("Apache", file.NewLocation("area!")),
				NewLicenseFromURLs("MIT", "https://github.com/anchore/syft/blob/main/LICENSE"),
				NewLicenseFromLocations("MIT", file.NewLocation("place!")),
				NewLicenseFromLocations("gpl2+", file.NewLocation("area!")),
			},
		},
		{
			name: "multiple with location variants",
			licenses: []License{
				NewLicenseFromLocations("MIT", file.NewLocation("place!")),
				NewLicenseFromLocations("MIT", file.NewLocation("park!")),
				NewLicense("MIT"),
				NewLicense("AAL"),
				NewLicense("Adobe-2006"),
				NewLicenseFromLocations("Apache", file.NewLocation("area!")),
			},
			expected: Licenses{
				NewLicense("AAL"),
				NewLicense("Adobe-2006"),
				NewLicenseFromLocations("Apache", file.NewLocation("area!")),
				NewLicense("MIT"),
				NewLicenseFromLocations("MIT", file.NewLocation("park!")),
				NewLicenseFromLocations("MIT", file.NewLocation("place!")),
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
