package pkg

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
)

func TestIDUniqueness(t *testing.T) {
	ctx := context.TODO()
	originalLocation := file.NewVirtualLocationFromCoordinates(
		file.NewCoordinates("39.0742° N, 21.8243° E", "Earth"),
		"/Ancient-Greece",
	)

	originalPkg := Package{
		Name:    "pi",
		Version: "3.14",
		FoundBy: "Archimedes",
		Locations: file.NewLocationSet(
			originalLocation,
		),
		Licenses: NewLicenseSet(
			NewLicenseWithContext(ctx, "MIT"),
			NewLicenseWithContext(ctx, "cc0-1.0"),
		),
		Language: "math",
		Type:     PythonPkg,
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`, cpe.NVDDictionaryLookupSource),
		},
		PURL: "pkg:pypi/pi@3.14",
		Metadata: PythonPackage{
			Name:                 "pi",
			Version:              "3.14",
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
				pkg.Metadata = PythonPackage{
					Name:                 "pi",
					Version:              "3.14",
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
				pkg.Licenses = NewLicenseSet(
					NewLicenseWithContext(ctx, "cc0-1.0"),
					NewLicenseWithContext(ctx, "MIT"),
				)
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
				locations := file.NewLocationSet(pkg.Locations.ToSlice()...)
				locations.Add(file.NewLocation("/somewhere/new"))
				pkg.Locations = locations
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "licenses is reflected",
			transform: func(pkg Package) Package {
				pkg.Licenses = NewLicenseSet(NewLicenseWithContext(ctx, "new!"))
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "same path for different filesystem is NOT reflected",
			transform: func(pkg Package) Package {
				newLocation := originalLocation
				newLocation.FileSystemID = "Mars"

				pkg.Locations = file.NewLocationSet(newLocation)
				return pkg
			},
			expectedIDComparison: assert.Equal,
		},
		{
			name: "multiple equivalent paths for different filesystem is NOT reflected",
			transform: func(pkg Package) Package {
				newLocation := originalLocation
				newLocation.FileSystemID = "Mars"

				locations := file.NewLocationSet(pkg.Locations.ToSlice()...)
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
			name: "type is reflected",
			transform: func(pkg Package) Package {
				pkg.Type = RustPkg
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
				metadata := pkg.Metadata.(PythonPackage)
				metadata.Name = "new!"
				pkg.Metadata = metadata
				return pkg
			},
			expectedIDComparison: assert.NotEqual,
		},
		{
			name: "new metadata is reflected",
			transform: func(pkg Package) Package {
				pkg.Metadata = PythonPackage{
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
	originalLocation := file.NewVirtualLocationFromCoordinates(
		file.NewCoordinates("39.0742° N, 21.8243° E", "Earth"),
		"/Ancient-Greece",
	)

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
				Locations: file.NewLocationSet(
					originalLocation,
				),
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`, cpe.NVDDictionaryLookupSource),
				},
				PURL: "pkg:pypi/pi@3.14",
				Metadata: PythonPackage{
					Name:                 "pi",
					Version:              "3.14",
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
				Locations: file.NewLocationSet(
					similarLocation, // NOTE: difference; we have a different layer but the same path
				),
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:DIFFERENT:pi:3.14:*:*:*:*:math:*:*`, cpe.NVDDictionaryLookupSource), // NOTE: difference
				},
				PURL: "pkg:pypi/pi@3.14",
				Metadata: PythonPackage{
					Name:                 "pi",
					Version:              "3.14",
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
				Locations: file.NewLocationSet(
					originalLocation,
					similarLocation, // NOTE: merge!
				),
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`, cpe.NVDDictionaryLookupSource),
					cpe.Must(`cpe:2.3:a:DIFFERENT:pi:3.14:*:*:*:*:math:*:*`, cpe.NVDDictionaryLookupSource), // NOTE: merge!
				},
				PURL: "pkg:pypi/pi@3.14",
				Metadata: PythonPackage{
					Name:                 "pi",
					Version:              "3.14",
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
				Locations: file.NewLocationSet(
					originalLocation,
				),
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`, cpe.NVDDictionaryLookupSource),
				},
				PURL: "pkg:pypi/pi@3.14",
				Metadata: PythonPackage{
					Name:                 "pi",
					Version:              "3.14",
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
				Locations: file.NewLocationSet(
					originalLocation,
				),
				Language: "math",
				Type:     PythonPkg,
				CPEs: []cpe.CPE{
					cpe.Must(`cpe:2.3:a:Archimedes:pi:3.14:*:*:*:*:math:*:*`, cpe.NVDDictionaryLookupSource),
				},
				PURL: "pkg:pypi/pi@3.14",
				Metadata: PythonPackage{
					Name:                 "pi",
					Version:              "3.14",
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
					func(x, y file.LocationSet) bool {
						xs := x.ToSlice()
						ys := y.ToSlice()

						if len(xs) != len(ys) {
							return false
						}
						for i, xe := range xs {
							ye := ys[i]
							if !locationComparer(xe, ye) {
								return false
							}
						}

						return true
					},
				),
				cmp.Comparer(
					func(x, y LicenseSet) bool {
						xs := x.ToSlice()
						ys := y.ToSlice()

						if len(xs) != len(ys) {
							return false
						}
						for i, xe := range xs {
							ye := ys[i]
							if !licenseComparer(xe, ye) {
								return false
							}
						}

						return true
					},
				),
				cmp.Comparer(locationComparer),
			); diff != "" {
				t.Errorf("unexpected result from parsing (-expected +actual)\n%s", diff)
			}
		})
	}
}

func licenseComparer(x, y License) bool {
	return cmp.Equal(x, y, cmp.Comparer(locationComparer))
}

func locationComparer(x, y file.Location) bool {
	return cmp.Equal(x.Coordinates, y.Coordinates) && cmp.Equal(x.AccessPath, y.AccessPath)
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

func TestID_nestedArchiveLocations(t *testing.T) {
	id := func(c file.Coordinates) string {
		p := Package{Name: "x", Version: "1", Type: NpmPkg, Locations: file.NewLocationSet(file.NewLocationFromCoordinates(c))}
		p.SetID()
		return string(p.ID())
	}

	assert.NotEqual(t,
		id(file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/a.jar!/package.json"}),
		id(file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/b.jar!/package.json"}),
		"packages in different entries of the same outer archive must not share an ID")

	assert.Equal(t,
		id(file.Coordinates{RealPath: "/package.json"}),
		id(file.NewCoordinates("/package.json", "")),
		"a full path equal to the real path must not change the ID")
}

func TestLess(t *testing.T) {
	newPkg := func(name, version string, ty Type, md any, paths ...string) Package {
		var locs []file.Location
		for _, p := range paths {
			locs = append(locs, file.NewLocation(p))
		}
		return Package{Name: name, Version: version, Type: ty, Metadata: md, Locations: file.NewLocationSet(locs...)}
	}
	md := func(resolved string) NpmPackageLockEntry { return NpmPackageLockEntry{Resolved: resolved} }

	cases := []struct {
		name string
		i, j Package
		want bool
	}{
		{
			name: "name-decides",
			i:    newPkg("a", "2", NpmPkg, md("z"), "/z"),
			j:    newPkg("b", "1", DotnetPkg, md("a"), "/a"),
			want: true,
		},
		{
			name: "version-decides",
			i:    newPkg("a", "2", NpmPkg, md("a"), "/a"),
			j:    newPkg("a", "1", DotnetPkg, md("z"), "/z"),
			want: false,
		},
		{
			name: "type-decides",
			i:    newPkg("a", "1", DotnetPkg, md("z"), "/z"),
			j:    newPkg("a", "1", NpmPkg, md("a"), "/a"),
			want: true,
		},
		{
			name: "location-path-decides",
			i:    newPkg("a", "1", NpmPkg, md("z"), "/a", "/z"),
			j:    newPkg("a", "1", NpmPkg, md("a"), "/b"),
			want: true,
		},
		{
			name: "fewer-locations-first",
			i:    newPkg("a", "1", NpmPkg, md("z"), "/a"),
			j:    newPkg("a", "1", NpmPkg, md("a"), "/a", "/b"),
			want: true,
		},
		{
			name: "metadata-decides",
			i:    newPkg("a", "1", NpmPkg, md("z"), "/a"),
			j:    newPkg("a", "1", NpmPkg, md("a"), "/a"),
			want: false,
		},
		{
			name: "equal",
			i:    newPkg("a", "1", NpmPkg, md("a"), "/a"),
			j:    newPkg("a", "1", NpmPkg, md("a"), "/a"),
			want: false,
		},
	}

	for _, c := range cases {
		require.Equal(t, c.want, Less(c.i, c.j), "when packages: %s", c.name)
	}
}

func TestSort_MatchesStableSortByLess(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 0))
	types := []Type{NpmPkg, DotnetPkg}
	for round := range 200 {
		// sizes incl 0 and 1, pkgs may lack locs
		pkgs := make([]Package, r.IntN(300))
		for i := range pkgs {
			var locs []file.Location
			for k := r.IntN(4) - 1; k >= 0; k-- {
				locs = append(locs, file.NewLocation(fmt.Sprintf("/p%d/package-lock.json", r.IntN(4))))
			}
			pkgs[i] = Package{
				Name:      fmt.Sprintf("n%d", r.IntN(4)),
				Version:   fmt.Sprintf("v%d", r.IntN(3)),
				Type:      types[r.IntN(len(types))],
				Locations: file.NewLocationSet(locs...),
				Metadata:  NpmPackageLockEntry{Resolved: fmt.Sprintf("r%d", r.IntN(2))},
				PURL:      fmt.Sprintf("identity-%d", i),
			}
		}

		want := slices.Clone(pkgs)
		sort.SliceStable(want, func(i, j int) bool { return Less(want[i], want[j]) })
		got := slices.Clone(pkgs)
		Sort(got)

		for i := range want {
			require.Equal(t, want[i].PURL, got[i].PURL, "round %d index %d", round, i)
		}

		// resorting sorted input keeps order
		Sort(got)
		for i := range want {
			require.Equal(t, want[i].PURL, got[i].PURL, "resort round %d index %d", round, i)
		}
	}
}

func BenchmarkSort(b *testing.B) {
	newPkg := func(name string, paths ...string) Package {
		var locs []file.Location
		for _, p := range paths {
			locs = append(locs, file.NewLocation(p))
		}
		return Package{Name: name, Version: "1.0.0", Type: NpmPkg, Locations: file.NewLocationSet(locs...)}
	}

	// dup deps across lockfiles: compare locations
	duplicates := func(lockfiles int) []Package {
		var pkgs []Package
		for l := range lockfiles {
			for i := range 1_000 {
				pkgs = append(pkgs, newPkg(fmt.Sprintf("package-%d", i), fmt.Sprintf("/svc-%d/package-lock.json", l)))
			}
		}
		return pkgs
	}
	// unique names: locations never compared
	unique := func(count int) []Package {
		pkgs := make([]Package, count)
		for i := range pkgs {
			pkgs[i] = newPkg(fmt.Sprintf("package-%d", (i*7919)%count), "/app/package-lock.json", "/app/node_modules/x/package.json")
		}
		return pkgs
	}
	// dup deps in one lockfile: compare metadata
	metadataTies := func(count int) []Package {
		pkgs := make([]Package, count)
		for i := range pkgs {
			pkgs[i] = newPkg(fmt.Sprintf("package-%d", i%100), "/app/package-lock.json")
			pkgs[i].Metadata = NpmPackageLockEntry{Resolved: fmt.Sprintf("https://registry.npmjs.org/package-%d.tgz", (i*7919)%count)}
		}
		return pkgs
	}
	presorted := func(count int) []Package {
		pkgs := unique(count)
		sort.SliceStable(pkgs, func(i, j int) bool { return Less(pkgs[i], pkgs[j]) })
		return pkgs
	}

	cases := []struct {
		name string
		pkgs []Package
	}{
		{name: "duplicates/packages=10000", pkgs: duplicates(10)},
		{name: "duplicates/packages=100000", pkgs: duplicates(100)},
		{name: "metadata-ties/packages=10000", pkgs: metadataTies(10_000)},
		{name: "unique/packages=100000", pkgs: unique(100_000)},
		{name: "presorted/packages=100000", pkgs: presorted(100_000)},
		{name: "small/packages=8", pkgs: unique(8)},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			work := make([]Package, len(tc.pkgs))
			for b.Loop() {
				copy(work, tc.pkgs)
				Sort(work)
			}
		})
	}
}
