package python

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
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
			name:    "simple dependencies with extras",
			fixture: "test-fixtures/poetry/simple-deps/poetry.lock",
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
							Requires: []string{"PySocks"},
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
