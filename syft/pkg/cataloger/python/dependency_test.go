package python

import (
	"context"
	"os"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func Test_poetryLockDependencySpecifier(t *testing.T) {

	tests := []struct {
		name string
		p    pkg.Package
		want dependency.Specification
	}{
		{
			name: "no dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPoetryLockEntry{
					Dependencies: []pkg.PythonPoetryLockDependencyEntry{},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
				},
			},
		},
		{
			name: "with required dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPoetryLockEntry{
					Dependencies: []pkg.PythonPoetryLockDependencyEntry{
						{
							Name:    "bar",
							Version: "1.2.3",
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: []string{"bar"},
				},
			},
		},
		{
			name: "with optional dependencies (explicit)",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPoetryLockEntry{
					Dependencies: []pkg.PythonPoetryLockDependencyEntry{
						{
							Name:     "bar",
							Version:  "1.2.3",
							Optional: true,
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: []string{"bar"},
				},
			},
		},
		{
			name: "without dependencies for non-required extra",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPoetryLockEntry{
					Dependencies: []pkg.PythonPoetryLockDependencyEntry{
						{
							Name:     "bar",
							Version:  "1.2.3",
							Optional: true,
							Markers:  "extra == 'baz'",
						},
					},
					// note: there is no "baz" extra defined
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: nil, // no requirements for non-required extra
				},
			},
		},
		{
			name: "package with extra",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPoetryLockEntry{
					Dependencies: []pkg.PythonPoetryLockDependencyEntry{
						{
							Name:     "bar", // note: we NEVER reference this, the extras section is the source of truth here
							Version:  "1.2.3",
							Optional: true,
							Markers:  "extra == 'baz'",
						},
					},
					Extras: []pkg.PythonPoetryLockExtraEntry{
						{
							Name: "baz",
							Dependencies: []string{
								"qux",
							},
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: nil, // no requirements for non-required extra
				},
				Variants: []dependency.ProvidesRequires{
					{
						Provides: []string{"foo[baz]"},
						Requires: []string{"qux"},
					},
				},
			},
		},
		{
			name: "package using extra",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPoetryLockEntry{
					Dependencies: []pkg.PythonPoetryLockDependencyEntry{
						{
							Name:    "starlette",
							Version: ">=0.37.2,<0.38.0",
						},
						{
							Name:    "bar",
							Version: "1.2.3",
							Extras:  []string{"standard", "things"}, // note multiple extras needed when installing
						},
					},
					Extras: []pkg.PythonPoetryLockExtraEntry{
						{
							Name: "baz",
							Dependencies: []string{
								"qux (>=2.0.0)", // should strip version constraint
							},
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: []string{
						"starlette",
						// note: we break out the package and extra requirements separately
						// and extras are never combined
						"bar",
						"bar[standard]",
						"bar[things]",
					},
				},
				Variants: []dependency.ProvidesRequires{
					{
						Provides: []string{"foo[baz]"},
						Requires: []string{"qux"},
					},
				},
			},
		},
		{
			name: "dependency names with mixed case should be normalized",
			p: pkg.Package{
				Name: "dj-rest-auth",
				Metadata: pkg.PythonPoetryLockEntry{
					Dependencies: []pkg.PythonPoetryLockDependencyEntry{
						{
							Name:    "Django", // note: capital D
							Version: ">=4.2,<6.0",
						},
						{
							Name:    "djangorestframework",
							Version: ">=3.13.0",
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"dj-rest-auth"},
					Requires: []string{"django", "djangorestframework"}, // "Django" should be normalized to "django"
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, poetryLockDependencySpecifier(tt.p))
		})
	}
}

func Test_poetryLockDependencySpecifier_againstPoetryLock(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    []dependency.Specification
	}{
		{
			name:    "case-insensitive dependency resolution",
			fixture: "testdata/poetry/case-sensitivity/poetry.lock",
			want: []dependency.Specification{
				// packages are in the order they appear in the lock file
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"django"},
						Requires: []string{"asgiref", "sqlparse"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"djangorestframework"},
						Requires: []string{"django"},
					},
				},
				{
					// dj-rest-auth depends on Django (capital D) which should resolve to django
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"dj-rest-auth"},
						Requires: []string{"django", "djangorestframework"}, // Django normalized to django
					},
					Variants: []dependency.ProvidesRequires{
						{
							Provides: []string{"dj-rest-auth[with-social]"},
							Requires: []string{"django-allauth"},
						},
					},
				},
			},
		},
		{
			name:    "simple dependencies with extras",
			fixture: "testdata/poetry/simple-deps/poetry.lock",
			want: []dependency.Specification{
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"certifi"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"charset-normalizer"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"idna"},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"requests"},
						Requires: []string{"certifi", "charset-normalizer", "idna", "urllib3"},
					},
					Variants: []dependency.ProvidesRequires{
						{
							Provides: []string{"requests[socks]"},
							Requires: []string{"pysocks"},
						},
						{
							Provides: []string{"requests[use-chardet-on-py3]"},
							Requires: []string{"chardet"},
						},
					},
				},
				{
					ProvidesRequires: dependency.ProvidesRequires{
						Provides: []string{"urllib3"},
					},
					Variants: []dependency.ProvidesRequires{
						{
							Provides: []string{"urllib3[brotli]"},
							Requires: []string{"brotli", "brotlicffi"},
						},
						{
							Provides: []string{"urllib3[h2]"},
							Requires: []string{"h2"}},
						{
							Provides: []string{"urllib3[socks]"},
							Requires: []string{"pysocks"},
						},
						{
							Provides: []string{"urllib3[zstd]"},
							Requires: []string{"zstandard"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fh, err := os.Open(tt.fixture)
			require.NoError(t, err)

			plp := newPoetryLockParser(DefaultCatalogerConfig())
			pkgs, err := plp.poetryLockPackages(context.TODO(), file.NewLocationReadCloser(file.NewLocation(tt.fixture), fh))
			require.NoError(t, err)

			var got []dependency.Specification
			for _, p := range pkgs {
				got = append(got, poetryLockDependencySpecifier(p))
			}

			if d := cmp.Diff(tt.want, got); d != "" {
				t.Errorf("wrong result (-want +got):\n%s", d)
			}
		})
	}
}

// Test_packageRef verifies that package references are normalized according to
// the Python Packaging specification for names and extras:
// https://packaging.python.org/en/latest/specifications/name-normalization/
func Test_packageRef(t *testing.T) {
	tests := []struct {
		name  string
		pkg   string
		extra string
		want  string
	}{
		{
			name: "simple package name",
			pkg:  "requests",
			want: "requests",
		},
		{
			name:  "package with extra",
			pkg:   "requests",
			extra: "security",
			want:  "requests[security]",
		},
		{
			name: "package name with mixed case",
			pkg:  "Django",
			want: "django",
		},
		{
			name: "package name with underscores",
			pkg:  "some_package",
			want: "some-package",
		},
		{
			name:  "package name with mixed case and extra",
			pkg:   "Django",
			extra: "argon2",
			want:  "django[argon2]",
		},
		{
			name:  "extra with mixed case",
			pkg:   "package",
			extra: "Security",
			want:  "package[security]",
		},
		{
			name:  "both with mixed case and separators",
			pkg:   "Some_Package",
			extra: "Dev_Extra",
			want:  "some-package[dev-extra]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := packageRef(tt.pkg, tt.extra)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_extractPackageName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple package name",
			input: "requests",
			want:  "requests",
		},
		{
			name:  "package with version constraint",
			input: "requests >= 2.8.1",
			want:  "requests",
		},
		{
			name:  "package with parentheses version constraint",
			input: "requests (>= 2.8.1)",
			want:  "requests",
		},
		{
			name:  "package with extras",
			input: "requests[security,tests]",
			want:  "requests",
		},
		{
			name:  "package with extras and version",
			input: "requests[security] >= 2.8.1",
			want:  "requests",
		},
		{
			name:  "package with environment marker",
			input: "requests ; python_version < \"2.7\"",
			want:  "requests",
		},
		{
			name:  "package with everything",
			input: "requests[security] >= 2.8.1 ; python_version < \"3\"",
			want:  "requests",
		},
		{
			name:  "package name with capitals (normalization test)",
			input: "Werkzeug (>=0.15)",
			want:  "werkzeug",
		},
		{
			name:  "package name with mixed case",
			input: "Jinja2 (>=2.10.1)",
			want:  "jinja2",
		},
		{
			name:  "package name with underscores",
			input: "some_package >= 1.0",
			want:  "some-package",
		},
		{
			name:  "package name with mixed separators",
			input: "Some_Package.Name >= 1.0",
			want:  "some-package-name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPackageName(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_wheelEggDependencySpecifier(t *testing.T) {
	tests := []struct {
		name string
		p    pkg.Package
		want dependency.Specification
	}{
		{
			name: "no dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPackage{
					RequiresDist: []string{},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
				},
			},
		},
		{
			name: "simple dependencies",
			p: pkg.Package{
				Name: "requests",
				Metadata: pkg.PythonPackage{
					RequiresDist: []string{
						"certifi>=2017.4.17",
						"urllib3<1.27,>=1.21.1",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"requests"},
					Requires: []string{"certifi", "urllib3"},
				},
			},
		},
		{
			name: "dependencies with capital letters (Flask-like)",
			p: pkg.Package{
				Name: "flask",
				Metadata: pkg.PythonPackage{
					RequiresDist: []string{
						"Werkzeug (>=0.15)",
						"Jinja2 (>=2.10.1)",
						"itsdangerous (>=0.24)",
						"click (>=5.1)",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"flask"},
					// Requires are returned in the order they appear in RequiresDist
					Requires: []string{"werkzeug", "jinja2", "itsdangerous", "click"},
				},
			},
		},
		{
			name: "dependencies with extras",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPackage{
					RequiresDist: []string{
						"bar >= 1.0",
						"pytest ; extra == 'dev'",
						"sphinx ; extra == 'docs'",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: []string{"bar", "pytest", "sphinx"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, wheelEggDependencySpecifier(tt.p))
		})
	}
}

func Test_pdmLockDependencySpecifier(t *testing.T) {

	tests := []struct {
		name string
		p    pkg.Package
		want dependency.Specification
	}{
		{
			name: "no dependencies",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPdmLockEntry{
					Dependencies: []string{},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
				},
			},
		},
		{
			name: "with simple dependencies",
			p: pkg.Package{
				Name: "requests",
				Metadata: pkg.PythonPdmLockEntry{
					Dependencies: []string{
						"certifi>=2017.4.17",
						"urllib3<1.27,>=1.21.1",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"requests"},
					Requires: []string{"certifi", "urllib3"},
				},
			},
		},
		{
			name: "with dependencies containing environment markers",
			p: pkg.Package{
				Name: "requests",
				Metadata: pkg.PythonPdmLockEntry{
					Dependencies: []string{
						"certifi>=2017.4.17",
						"chardet<5,>=3.0.2; python_version < \"3\"",
						"charset-normalizer~=2.0.0; python_version >= \"3\"",
						"idna<3,>=2.5; python_version < \"3\"",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"requests"},
					Requires: []string{"certifi", "chardet", "charset-normalizer", "idna"},
				},
			},
		},
		{
			name: "with dependencies containing extras",
			p: pkg.Package{
				Name: "pytest-cov",
				Metadata: pkg.PythonPdmLockEntry{
					Dependencies: []string{
						"coverage[toml]>=5.2.1",
						"pytest>=4.6",
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"pytest-cov"},
					Requires: []string{"coverage", "pytest"},
				},
			},
		},
		{
			name: "package with single extra variant",
			p: pkg.Package{
				Name: "coverage",
				Metadata: pkg.PythonPdmLockEntry{
					Dependencies: []string{}, // base package has no dependencies
					Extras: []pkg.PythonPdmLockExtraVariant{
						{
							Extras: []string{"toml"},
							Dependencies: []string{
								"coverage==7.4.1", // self-reference, should be excluded
								"tomli; python_full_version <= \"3.11.0a6\"",
							},
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"coverage"},
					Requires: nil,
				},
				Variants: []dependency.ProvidesRequires{
					{
						Provides: []string{"coverage[toml]"},
						Requires: []string{"tomli"}, // coverage self-reference excluded
					},
				},
			},
		},
		{
			name: "package with multiple extras in one variant",
			p: pkg.Package{
				Name: "foo",
				Metadata: pkg.PythonPdmLockEntry{
					Dependencies: []string{"bar>=1.0"},
					Extras: []pkg.PythonPdmLockExtraVariant{
						{
							Extras: []string{"dev", "test"},
							Dependencies: []string{
								"pytest>=6.0",
								"black~=22.0",
								"foo==1.0.0", // self-reference, should be excluded
							},
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"foo"},
					Requires: []string{"bar"},
				},
				Variants: []dependency.ProvidesRequires{
					{
						Provides: []string{"foo[dev]", "foo[test]"},
						Requires: []string{"pytest", "black"}, // foo self-reference excluded
					},
				},
			},
		},
		{
			name: "package with multiple separate extra variants",
			p: pkg.Package{
				Name: "example",
				Metadata: pkg.PythonPdmLockEntry{
					Dependencies: []string{"requests"},
					Extras: []pkg.PythonPdmLockExtraVariant{
						{
							Extras:       []string{"redis"},
							Dependencies: []string{"redis>=4.0"},
						},
						{
							Extras:       []string{"postgres"},
							Dependencies: []string{"psycopg2>=2.9"},
						},
					},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"example"},
					Requires: []string{"requests"},
				},
				Variants: []dependency.ProvidesRequires{
					{
						Provides: []string{"example[redis]"},
						Requires: []string{"redis"},
					},
					{
						Provides: []string{"example[postgres]"},
						Requires: []string{"psycopg2"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, pdmLockDependencySpecifier(tt.p))
		})
	}
}

func Test_wheelEggRelationships_duplicateDistributionName(t *testing.T) {
	newPkg := func(name, version, metadataPath string, requires ...string) pkg.Package {
		p := pkg.Package{
			Name:    name,
			Version: version,
			Type:    pkg.PythonPkg,
			Locations: file.NewLocationSet(
				file.NewLocationFromCoordinates(file.Coordinates{RealPath: metadataPath}).
					WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
			Metadata: pkg.PythonPackage{
				Name:         name,
				Version:      version,
				RequiresDist: requires,
			},
		}
		p.SetID()
		return p
	}

	const site = "/usr/lib/python3/dist-packages"

	tests := []struct {
		name string
		pkgs []pkg.Package
		// dependant package name -> versions of the packages it should depend on
		want map[string][]string
	}{
		{
			name: "single provider is unaffected",
			pkgs: []pkg.Package{
				newPkg("packaging", "24.0", site+"/packaging-24.0.dist-info/METADATA"),
				newPkg("gunicorn", "23.0.0", site+"/gunicorn-23.0.0.dist-info/METADATA", "packaging"),
			},
			want: map[string][]string{"gunicorn": {"packaging@24.0"}},
		},
		{
			name: "top level install wins over a vendored copy",
			pkgs: []pkg.Package{
				newPkg("packaging", "24.0", site+"/packaging-24.0.dist-info/METADATA"),
				newPkg("packaging", "26.0", site+"/setuptools/_vendor/packaging-26.0.dist-info/METADATA"),
				newPkg("gunicorn", "23.0.0", site+"/gunicorn-23.0.0.dist-info/METADATA", "packaging"),
			},
			want: map[string][]string{"gunicorn": {"packaging@24.0"}},
		},
		{
			name: "target directory without a site-packages name",
			pkgs: []pkg.Package{
				newPkg("packaging", "26.0", "/app/python"+"/setuptools/_vendor/packaging-26.0.dist-info/METADATA"),
				newPkg("gunicorn", "23.0.0", "/app/python"+"/gunicorn-23.0.0.dist-info/METADATA", "packaging"),
				newPkg("packaging", "24.0", "/app/python"+"/packaging-24.0.dist-info/METADATA"),
			},
			want: map[string][]string{"gunicorn": {"packaging@24.0"}},
		},
		{
			name: "equal depth falls back to a stable tiebreak on path",
			pkgs: []pkg.Package{
				newPkg("packaging", "26.0", site+"/b/packaging-26.0.dist-info/METADATA"),
				newPkg("packaging", "24.0", site+"/a/packaging-24.0.dist-info/METADATA"),
				newPkg("gunicorn", "23.0.0", site+"/gunicorn-23.0.0.dist-info/METADATA", "packaging"),
			},
			want: map[string][]string{"gunicorn": {"packaging@24.0"}},
		},
		{
			name: "separate site-packages directories stay independent",
			pkgs: []pkg.Package{
				newPkg("packaging", "24.0", "/one/site-packages/packaging-24.0.dist-info/METADATA"),
				newPkg("packaging", "26.0", "/two/site-packages/packaging-26.0.dist-info/METADATA"),
				newPkg("gunicorn", "23.0.0", "/one/site-packages/gunicorn-23.0.0.dist-info/METADATA", "packaging"),
				newPkg("build", "1.2.2", "/two/site-packages/build-1.2.2.dist-info/METADATA", "packaging"),
			},
			want: map[string][]string{"gunicorn": {"packaging@24.0"}, "build": {"packaging@26.0"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs := append([]pkg.Package(nil), tt.pkgs...)
			var checkPermutations func(int)
			checkPermutations = func(start int) {
				if start < len(pkgs) {
					for i := start; i < len(pkgs); i++ {
						pkgs[start], pkgs[i] = pkgs[i], pkgs[start]
						checkPermutations(start + 1)
						pkgs[start], pkgs[i] = pkgs[i], pkgs[start]
					}
					return
				}

				gotPkgs, rels, err := wheelEggRelationships(context.Background(), fileresolver.Empty{}, pkgs, nil, nil)
				require.NoError(t, err)
				require.ElementsMatch(t, tt.pkgs, gotPkgs, "retain every cataloged package")

				got := make(map[string][]string)
				for _, rel := range rels {
					from, ok := rel.From.(pkg.Package)
					require.True(t, ok)
					to, ok := rel.To.(pkg.Package)
					require.True(t, ok)
					// DependencyOf points from the provider to the dependant.
					got[to.Name] = append(got[to.Name], from.Name+"@"+from.Version)
				}
				for k := range got {
					sort.Strings(got[k])
				}
				require.Equal(t, tt.want, got)
			}
			checkPermutations(0)
		})
	}
}

func Test_preferShallowest(t *testing.T) {
	primary := func(p string) file.Location {
		return file.NewLocation(p).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)
	}
	newPkg := func(version string, locations ...file.Location) pkg.Package {
		p := pkg.Package{Name: "example", Version: version, Locations: file.NewLocationSet(locations...)}
		p.SetID()
		return p
	}
	check := func(t *testing.T, a, b, want pkg.Package) {
		t.Helper()
		require.Equal(t, want.ID(), preferShallowest(a, b).ID())
		require.Equal(t, want.ID(), preferShallowest(b, a).ID())
	}

	t.Run("supporting evidence does not outrank primary metadata", func(t *testing.T) {
		nested := newPkg("1", primary("/site-packages/vendor/example.dist-info/METADATA"), file.NewLocation("/LICENSE"))
		top := newPkg("2", primary("/site-packages/example.dist-info/METADATA"))
		check(t, nested, top, top)
	})
	t.Run("equal paths fall back to package ID", func(t *testing.T) {
		a := newPkg("1", primary("/site-packages/example.dist-info/METADATA"))
		b := newPkg("2", primary("/site-packages/example.dist-info/METADATA"))
		want := a
		if b.ID() < a.ID() {
			want = b
		}
		check(t, a, b, want)
	})
	t.Run("known location wins over missing location", func(t *testing.T) {
		unknown := newPkg("1")
		known := newPkg("2", file.NewLocation("/example.dist-info/METADATA"))
		check(t, unknown, known, known)
	})
}
