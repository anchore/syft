package python

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseRequirementsTxt(t *testing.T) {
	fixture := "test-fixtures/requires/requirements.txt"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	pinnedPkgs := []pkg.Package{
		{
			Name:      "flask",
			Version:   "4.0.0",
			PURL:      "pkg:pypi/flask@4.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "flask",
				VersionConstraint: "== 4.0.0",
			},
		},
		{
			Name:      "foo",
			Version:   "1.0.0",
			PURL:      "pkg:pypi/foo@1.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "foo",
				VersionConstraint: "== 1.0.0",
			},
		},
		{
			Name:      "someproject",
			Version:   "5.4",
			PURL:      "pkg:pypi/someproject@5.4",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "SomeProject",
				VersionConstraint: "==5.4",
				Markers:           "python_version < '3.8'",
			},
		},
		{
			Name:      "dots-allowed",
			Version:   "1.0.0",
			PURL:      "pkg:pypi/dots-allowed@1.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "dots-._allowed",
				VersionConstraint: "== 1.0.0",
			},
		},
		{
			Name:      "argh",
			Version:   "0.26.2",
			PURL:      "pkg:pypi/argh@0.26.2",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "argh",
				VersionConstraint: "==0.26.2",
			},
		},
		{
			Name:      "argh",
			Version:   "0.26.3",
			PURL:      "pkg:pypi/argh@0.26.3",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "argh",
				VersionConstraint: "==0.26.3",
			},
		},
		{
			Name:      "celery",
			Version:   "4.4.7",
			PURL:      "pkg:pypi/celery@4.4.7",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "celery",
				Extras:            []string{"redis", "pytest"},
				VersionConstraint: "== 4.4.7",
			},
		},
		{
			Name:      "githubsampleproject",
			Version:   "3.7.1",
			PURL:      "pkg:pypi/githubsampleproject@3.7.1",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "GithubSampleProject",
				VersionConstraint: "== 3.7.1",
				URL:               "git+https://github.com/owner/repo@releases/tag/v3.7.1",
			},
		},
		{
			Name:      "friendly-bard",
			Version:   "1.0.0",
			PURL:      "pkg:pypi/friendly-bard@1.0.0",
			Locations: locations,
			Language:  pkg.Python,
			Type:      pkg.PythonPkg,
			Metadata: pkg.PythonRequirementsEntry{
				Name:              "FrIeNdLy-_-bArD",
				VersionConstraint: "== 1.0.0",
			},
		},
	}

	var testCases = []struct {
		name                  string
		fixture               string
		cfg                   CatalogerConfig
		expectedPkgs          []pkg.Package
		expectedRelationships []artifact.Relationship
	}{
		{
			name:    "pinned dependencies only",
			fixture: fixture,
			cfg: CatalogerConfig{
				GuessUnpinnedRequirements: false,
			},
			expectedPkgs: pinnedPkgs,
		},
		{
			name:    "guess unpinned requirements (lowest version)",
			fixture: fixture,
			cfg: CatalogerConfig{
				GuessUnpinnedRequirements: true,
			},
			expectedPkgs: append([]pkg.Package{
				{
					Name:      "mopidy-dirble",
					Version:   "1.1",
					PURL:      "pkg:pypi/mopidy-dirble@1.1",
					Locations: locations,
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonRequirementsEntry{
						Name:              "Mopidy-Dirble",
						VersionConstraint: "~= 1.1",
					},
				},
				{
					Name:      "sqlalchemy",
					Version:   "2.0.0",
					PURL:      "pkg:pypi/sqlalchemy@2.0.0",
					Locations: locations,
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonRequirementsEntry{
						Name:              "sqlalchemy",
						VersionConstraint: ">= 1.0.0, <= 2.0.0, != 3.0.0, <= 3.0.0",
					},
				},
				{
					Name:      "bar",
					Version:   "2.0.0",
					PURL:      "pkg:pypi/bar@2.0.0",
					Locations: locations,
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonRequirementsEntry{
						Name:              "bar",
						VersionConstraint: ">= 1.0.0, <= 2.0.0, != 3.0.0, <= 3.0.0",
					},
				},
				{
					Name:      "numpy",
					Version:   "3.4.1",
					PURL:      "pkg:pypi/numpy@3.4.1",
					Locations: locations,
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonRequirementsEntry{
						Name:              "numpy",
						VersionConstraint: ">= 3.4.1",
						Markers:           `sys_platform == 'win32'`,
					},
				},
				{
					Name:      "requests",
					Version:   "2.8.0",
					PURL:      "pkg:pypi/requests@2.8.0",
					Locations: locations,
					Language:  pkg.Python,
					Type:      pkg.PythonPkg,
					Metadata: pkg.PythonRequirementsEntry{
						Name:              "requests",
						Extras:            []string{"security"},
						VersionConstraint: "== 2.8.*",
						Markers:           `python_version < "2.7" and sys_platform == "linux"`,
					},
				},
			}, pinnedPkgs...),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := newRequirementsParser(tc.cfg)
			pkgtest.TestFileParser(t, tc.fixture, parser.parseRequirementsTxt, tc.expectedPkgs, tc.expectedRelationships)
		})
	}
}

func Test_newRequirement(t *testing.T) {

	tests := []struct {
		name string
		raw  string
		want *unprocessedRequirement
	}{
		{
			name: "simple",
			raw:  "requests==2.8",
			want: &unprocessedRequirement{
				Name:              "requests",
				VersionConstraint: "==2.8",
			},
		},
		{
			name: "comment + constraint",
			raw:  "Mopidy-Dirble ~= 1.1 # Compatible release. Same as >= 1.1, == 1.*",
			want: &unprocessedRequirement{
				Name:              "Mopidy-Dirble",
				VersionConstraint: "~= 1.1",
			},
		},
		{
			name: "hashes",
			raw:  "argh==0.26.3 --hash=sha256:a9b3aaa1904eeb78e32394cd46c6f37ac0fb4af6dc488daa58971bdc7d7fcaf3 --hash=sha256:e9535b8c84dc9571a48999094fda7f33e63c3f1b74f3e5f3ac0105a58405bb65",
			want: &unprocessedRequirement{
				Name:              "argh",
				VersionConstraint: "==0.26.3",
				Hashes:            "--hash=sha256:a9b3aaa1904eeb78e32394cd46c6f37ac0fb4af6dc488daa58971bdc7d7fcaf3 --hash=sha256:e9535b8c84dc9571a48999094fda7f33e63c3f1b74f3e5f3ac0105a58405bb65",
			},
		},
		{
			name: "extras",
			raw:  "celery[redis, pytest] == 4.4.7 # should remove [redis, pytest]",
			want: &unprocessedRequirement{
				Name:              "celery[redis, pytest]",
				VersionConstraint: "== 4.4.7",
			},
		},
		{
			name: "url",
			raw:  "GithubSampleProject == 3.7.1 @ git+https://github.com/owner/repo@releases/tag/v3.7.1",
			want: &unprocessedRequirement{
				Name:              "GithubSampleProject",
				VersionConstraint: "== 3.7.1",
				URL:               "git+https://github.com/owner/repo@releases/tag/v3.7.1",
			},
		},
		{
			name: "markers",
			raw:  "numpy >= 3.4.1 ; sys_platform == 'win32'",
			want: &unprocessedRequirement{
				Name:              "numpy",
				VersionConstraint: ">= 3.4.1",
				Markers:           "sys_platform == 'win32'",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, newRequirement(tt.raw))
		})
	}
}

// checkout https://www.darius.page/pipdev/ for help here! (github.com/nok/pipdev)
func Test_parseVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		guess   bool
		want    string
	}{
		{
			name:    "exact",
			version: "1.0.0",
			want:    "", // we can only parse constraints, not assume that a single version is a pin
		},
		{
			name:    "exact constraint",
			version: " == 1.0.0 ",
			want:    "1.0.0",
		},
		{
			name:    "resolve lowest, simple constraint",
			version: " >= 1.0.0 ",
			guess:   true,
			want:    "1.0.0",
		},
		{
			name:    "resolve lowest, compound constraint",
			version: "  < 2.0.0,  >= 1.0.0, != 1.1.0 ",
			guess:   true,
			want:    "1.0.0",
		},
		{
			name:    "resolve lowest, handle asterisk",
			version: "==2.8.*",
			guess:   true,
			want:    "2.8.0",
		},
		{
			name:    "resolve lowest, handle exceptions",
			version: " !=4.0.2,!=4.1.0,!=4.2.0,>=4.0.1,!=4.3.0,!=5.0.0,!=5.1.0,<6.0.0",
			guess:   true,
			want:    "4.0.1",
		},
		{
			name:    "resolve lowest, compatible version constraint",
			version: "~=0.6.10", // equates to >=0.6.10, ==0.6.*
			guess:   true,
			want:    "0.6.10",
		},
		{
			name:    "resolve lowest, with character in version",
			version: "~=1.2b,<=1.3a,!=1.1,!=1.2",
			guess:   true,
			want:    "1.3a0", // note: 1.3a == 1.3a0
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseVersion(tt.version, tt.guess))
		})
	}
}

func Test_corruptRequirementsTxt(t *testing.T) {
	rp := newRequirementsParser(DefaultCatalogerConfig())
	pkgtest.NewCatalogTester().
		FromFile(t, "test-fixtures/glob-paths/src/requirements.txt").
		WithError().
		TestParser(t, rp.parseRequirementsTxt)
}
