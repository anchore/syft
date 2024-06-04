package python

import (
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

			pkgs, err := poetryLockPackages(file.NewLocationReadCloser(file.NewLocation(tt.fixture), fh))
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
