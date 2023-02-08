package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/source"
)

func TestIDUniqueness(t *testing.T) {
	originalLocation := source.Location{
		Coordinates: source.Coordinates{
			RealPath:     "39.0742° N, 21.8243° E",
			FileSystemID: "Earth",
		},
		VirtualPath: "/Ancient-Greece",
	}
	originalPkg := Package{
		Name:    "pi",
		Version: "3.14",
		FoundBy: "Archimedes",
		Locations: source.NewLocationSet(
			originalLocation,
		),
		Licenses: internal.LogicalStrings{
			Simple: []string{
				"cc0-1.0",
				"MIT",
			},
		},
		Language: "math",
		Type:     PythonPkg,
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`),
		},
		PURL:         "pkg:pypi/pi@3.14",
		MetadataType: PythonPackageMetadataType,
		Metadata: PythonPackageMetadata{
			Name:                 "pi",
			Version:              "3.14",
			License:              "cc0-1.0",
			Author:               "Archimedes",
			AuthorEmail:          "Archimedes@circles.io",
			Platform:             "universe",
			SitePackagesRootPath: "Pi",
		},
	}

	// this is a set of differential tests, ensuring that select mutations are reflected in the fingerprint (or not)
	tests := []struct {
		name                 string
		transform            func(pkg Package) Package
		expectedIDComparison assert.ComparisonAssertionFunc
	}{
		{
			name: "go case (no transform)",
			transform: func(pkg Package) Package {
				// do nothing!
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "same metadata is ignored",
			transform: func(pkg Package) Package {
				// note: this is the same as the original values, just a new allocation
				pkg.Metadata = PythonPackageMetadata{
					Name:                 "pi",
					Version:              "3.14",
					License:              "cc0-1.0",
					Author:               "Archimedes",
					AuthorEmail:          "Archimedes@circles.io",
					Platform:             "universe",
					SitePackagesRootPath: "Pi",
				}
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "licenses order is ignored",
			transform: func(pkg Package) Package {
				// note: same as the original package, only a different order
				pkg.Licenses = internal.LogicalStrings{
					Simple: []string{
						"MIT",
						"cc0-1.0",
					},
				}
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "name is reflected",
			transform: func(pkg Package) Package {
				pkg.Name = "new!"
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "location is reflected",
			transform: func(pkg Package) Package {
				locations := source.NewLocationSet(pkg.Locations.ToSlice()...)
				locations.Add(source.NewLocation("/somewhere/new"))
				pkg.Locations = locations
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "same path for different filesystem is NOT reflected",
			transform: func(pkg Package) Package {
				newLocation := originalLocation
				newLocation.FileSystemID = "Mars"

				pkg.Locations = source.NewLocationSet(newLocation)
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "multiple equivalent paths for different filesystem is NOT reflected",
			transform: func(pkg Package) Package {
				newLocation := originalLocation
				newLocation.FileSystemID = "Mars"

				locations := source.NewLocationSet(pkg.Locations.ToSlice()...)
				locations.Add(newLocation, originalLocation)

				pkg.Locations = locations
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "version is reflected",
			transform: func(pkg Package) Package {
				pkg.Version = "new!"
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "licenses is reflected",
			transform: func(pkg Package) Package {
				pkg.Licenses = internal.LogicalStrings{Simple: []string{"new!"}}
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "type is reflected",
			transform: func(pkg Package) Package {
				pkg.Type = RustPkg
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "metadata type is reflected",
			transform: func(pkg Package) Package {
				pkg.MetadataType = RustCargoPackageMetadataType
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "CPEs is ignored",
			transform: func(pkg Package) Package {
				pkg.CPEs = []cpe.CPE{}
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "pURL is ignored",
			transform: func(pkg Package) Package {
				pkg.PURL = "new!"
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "language is NOT reflected",
			transform: func(pkg Package) Package {
				pkg.Language = Rust
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "metadata mutation is reflected",
			transform: func(pkg Package) Package {
				metadata := pkg.Metadata.(PythonPackageMetadata)
				metadata.Name = "new!"
				pkg.Metadata = metadata
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "new metadata is reflected",
			transform: func(pkg Package) Package {
				pkg.Metadata = PythonPackageMetadata{
					Name: "new!",
				}
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "nil metadata is reflected",
			transform: func(pkg Package) Package {
				pkg.Metadata = nil
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalPkg.SetID()
			transformedPkg := test.transform(originalPkg)
			transformedPkg.SetID()

			originalFingerprint := originalPkg.ID()
			assert.NotEmpty(t, originalFingerprint)
			transformedFingerprint := transformedPkg.ID()
			assert.NotEmpty(t, transformedFingerprint)

			test.expectedIDComparison(t, originalFingerprint, transformedFingerprint)
		})
	}
}

func TestPackage_Merge(t *testing.T) {
	originalLocation := source.Location{
		Coordinates: source.Coordinates{
			RealPath:     "39.0742° N, 21.8243° E",
			FileSystemID: "Earth",
		},
		VirtualPath: "/Ancient-Greece",
	}

	similarLocation := originalLocation
	similarLocation.FileSystemID = "Mars"

	tests := []struct {
		name     string
		subject  Package
		other    Package
		expected *Package
	}{
		{
			name: "merge two packages (different cpes + locations)",
			subject: Package{
				Name:    "pi",
				Version: "3.14",
				FoundBy: "Archimedes",
				Locations: source.NewLocationSet(
					originalLocation,
				),
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"cc0-1.0",
						"MIT",
					},
				},
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`),
				},
				PURL:         "pkg:pypi/pi@3.14",
				MetadataType: PythonPackageMetadataType,
				Metadata: PythonPackageMetadata{
					Name:                 "pi",
					Version:              "3.14",
					License:              "cc0-1.0",
					Author:               "Archimedes",
					AuthorEmail:          "Archimedes@circles.io",
					Platform:             "universe",
					SitePackagesRootPath: "Pi",
				},
			},
			other: Package{
				Name:    "pi",
				Version: "3.14",
				FoundBy: "Archimedes",
				Locations: source.NewLocationSet(
					similarLocation, // NOTE: difference; we have a different layer but the same path
				),
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"cc0-1.0",
						"MIT",
					},
				},
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:DIFFERENT:pi:3.14:*:*:*:*:math:*:*`), // NOTE: difference
				},
				PURL:         "pkg:pypi/pi@3.14",
				MetadataType: PythonPackageMetadataType,
				Metadata: PythonPackageMetadata{
					Name:                 "pi",
					Version:              "3.14",
					License:              "cc0-1.0",
					Author:               "Archimedes",
					AuthorEmail:          "Archimedes@circles.io",
					Platform:             "universe",
					SitePackagesRootPath: "Pi",
				},
			},
			expected: &Package{
				Name:    "pi",
				Version: "3.14",
				FoundBy: "Archimedes",
				Locations: source.NewLocationSet(
					originalLocation,
					similarLocation, // NOTE: merge!
				),
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"cc0-1.0",
						"MIT",
					},
				},
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`),
					cpe.Must(`cpe:2.3:a:DIFFERENT:pi:3.14:*:*:*:*:math:*:*`), // NOTE: merge!
				},
				PURL:         "pkg:pypi/pi@3.14",
				MetadataType: PythonPackageMetadataType,
				Metadata: PythonPackageMetadata{
					Name:                 "pi",
					Version:              "3.14",
					License:              "cc0-1.0",
					Author:               "Archimedes",
					AuthorEmail:          "Archimedes@circles.io",
					Platform:             "universe",
					SitePackagesRootPath: "Pi",
				},
			},
		},
		{
			name: "error when there are different IDs",
			subject: Package{
				Name:    "pi",
				Version: "3.14",
				FoundBy: "Archimedes",
				Locations: source.NewLocationSet(
					originalLocation,
				),
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"cc0-1.0",
						"MIT",
					},
				},
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`),
				},
				PURL:         "pkg:pypi/pi@3.14",
				MetadataType: PythonPackageMetadataType,
				Metadata: PythonPackageMetadata{
					Name:                 "pi",
					Version:              "3.14",
					License:              "cc0-1.0",
					Author:               "Archimedes",
					AuthorEmail:          "Archimedes@circles.io",
					Platform:             "universe",
					SitePackagesRootPath: "Pi",
				},
			},
			other: Package{
				Name:    "pi-DIFFERENT", // difference
				Version: "3.14",
				FoundBy: "Archimedes",
				Locations: source.NewLocationSet(
					originalLocation,
				),
				Licenses: internal.LogicalStrings{
					Simple: []string{
						"cc0-1.0",
						"MIT",
					},
				},
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`),
				},
				PURL:         "pkg:pypi/pi@3.14",
				MetadataType: PythonPackageMetadataType,
				Metadata: PythonPackageMetadata{
					Name:                 "pi",
					Version:              "3.14",
					License:              "cc0-1.0",
					Author:               "Archimedes",
					AuthorEmail:          "Archimedes@circles.io",
					Platform:             "universe",
					SitePackagesRootPath: "Pi",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.subject.SetID()
			tt.other.SetID()

			err := tt.subject.merge(tt.other)
			if tt.expected == nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			tt.expected.SetID()
			require.Equal(t, tt.expected.id, tt.subject.id)

			if diff := cmp.Diff(*tt.expected, tt.subject,
				cmp.AllowUnexported(Package{}),
				cmp.Comparer(
					func(x, y source.LocationSet) bool {
						return cmp.Equal(
							x.ToSlice(), y.ToSlice(),
							cmp.AllowUnexported(source.Location{}),
							cmp.AllowUnexported(file.Reference{}),
						)
					},
				),
			); diff != "" {
				t.Errorf("unexpected result from parsing (-expected +actual)\n%s", diff)
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	cases := []struct {
		name  string
		given *Package
		want  bool
	}{
		{
			name:  "nil",
			given: nil,
			want:  false,
		},
		{
			name:  "has-name",
			given: &Package{Name: "paul"},
			want:  true,
		},
		{
			name:  "has-no-name",
			given: &Package{},
			want:  false,
		},
	}

	for _, c := range cases {
		require.Equal(t, c.want, IsValid(c.given), "when package: %s", c.name)
	}
}
