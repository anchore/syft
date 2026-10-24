package perl

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

// the record shape here is cpanm's, reduced to the fields the parser reads. What matters is that
// `name` is the module (CPAN::02Packages::Search) and must not become the package name, and that the
// version is a v-string, which the split of `dist` has to keep whole rather than treat as three segments.
//
// The byte-level shape of what the clients really write is covered against real files by
// TestInstallJSON_clientFormatting.
const installJSONFixture = `{"target":"CPAN::02Packages::Search","module_name":"CPAN::02Packages::Search",` +
	`"version":"v1.0.0","dist":"CPAN-02Packages-Search-v1.0.0","pathname":"S/SK/SKAJI/CPAN-02Packages-Search-v1.0.0.tar.gz",` +
	`"provides":{"CPAN::02Packages::Search":{"file":"lib/CPAN/02Packages/Search.pm","version":"v1.0.0"}},` +
	`"name":"CPAN::02Packages::Search"}`

func TestParseInstallJSON(t *testing.T) {
	const location = "usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux-gnu/.meta/CPAN-02Packages-Search-v1.0.0/install.json"

	expected := []pkg.Package{
		{
			Name:      "CPAN-02Packages-Search",
			Version:   "v1.0.0",
			PURL:      "pkg:cpan/CPAN-02Packages-Search@v1.0.0?author=SKAJI",
			Locations: file.NewLocationSet(file.NewLocation(location)),
			Language:  pkg.Perl,
			Type:      pkg.CpanPkg,
			Metadata: pkg.CpanDistribution{
				Dist:   "CPAN-02Packages-Search-v1.0.0",
				Author: "SKAJI",
				Path:   "S/SK/SKAJI/CPAN-02Packages-Search-v1.0.0.tar.gz",
				// the provides map, sorted by module name, with per-module versions: a distribution
				// built with inherit_version = 0 ships modules at versions other than its own
				Modules: []pkg.CpanModule{
					{Name: "CPAN::02Packages::Search", Version: "v1.0.0"},
				},
			},
		},
	}

	// no MYMETA.json is reachable from a single-string resolver, so the package is reported with no
	// licenses and no error
	pkgtest.NewCatalogTester().
		FromString(location, installJSONFixture).
		Expects(expected, []artifact.Relationship(nil)).
		TestParser(t, parseInstallJSON)
}

// libwww-perl is the canonical name mismatch: `name` is LWP while the distribution every advisory and
// index is filed against is libwww-perl. Reporting LWP here is the bug this guards. The end-to-end
// form of it is TestCpanInstalledCataloger_mirrorInstallEvidence.
func TestParseInstallJSON_distributionNameNotModuleName(t *testing.T) {
	const record = `{"name":"LWP","version":"6.83","dist":"libwww-perl-6.83",` +
		`"pathname":"O/OA/OALDERS/libwww-perl-6.83.tar.gz",` +
		`"provides":{"LWP":{"file":"lib/LWP.pm","version":"6.83"},"LWP::UserAgent":{"file":"lib/LWP/UserAgent.pm","version":"6.83"}}}`

	pkgs := parseString(t, "libwww-perl-6.83/install.json", record)
	require.Len(t, pkgs, 1)

	assert.Equal(t, "libwww-perl", pkgs[0].Name, "the package name must be the distribution, not the LWP module")
	assert.Equal(t, "pkg:cpan/libwww-perl@6.83?author=OALDERS", pkgs[0].PURL)

	// the module name is not lost, it belongs in the provides map
	assert.Equal(t, []string{"LWP", "LWP::UserAgent"}, providedModules(pkgs[0]))
}

// TestInstallJSON_clientFormatting records what was measured about cpm versus cpanm, since the
// question of whether cpm needs its own coverage kept coming up. Both files are read out of the
// image, where cpanm (through carton) and cpm each installed one distribution.
//
// Finding: they are NOT byte-identical. cpanm writes compact JSON with no trailing newline; cpm writes
// canonical JSON, indented three spaces with spaces around the colons and a trailing newline. The
// record itself has the same shape, including `dist` carrying the version suffix, which is worth
// stating because it is the field the distribution name is derived from.
//
// So anything that reads these files by decoding JSON is unaffected by the difference; anything that
// pattern matches the bytes is not.
func TestInstallJSON_clientFormatting(t *testing.T) {
	resolver := imageResolver(t, "image-cpan-mirror-installs")

	read := func(path string) string {
		locations, err := resolver.FilesByPath(path)
		require.NoError(t, err)
		require.Len(t, locations, 1, path)

		reader, err := resolver.FileContentsByLocation(locations[0])
		require.NoError(t, err)
		defer internal.CloseAndLogError(reader, path)

		contents, err := io.ReadAll(reader)
		require.NoError(t, err)
		return string(contents)
	}

	// written by cpanm, which carton shells out to
	cpanmWritten := read("/app/local/lib/perl5/x86_64-linux-gnu/.meta/Text-CSV-2.06/install.json")
	cpmWritten := read("/srv/api/local/lib/perl5/x86_64-linux-gnu/.meta/Capture-Tiny-0.48/install.json")

	assert.NotContains(t, cpanmWritten, "\n", "cpanm writes a single compact line")
	assert.Contains(t, cpmWritten, "\"dist\" : ", "cpm writes canonical JSON, with spaces around the colons")
	assert.Contains(t, cpmWritten, "\n", "and a trailing newline")

	var fromCpanm, fromCpm installJSON
	require.NoError(t, json.Unmarshal([]byte(cpanmWritten), &fromCpanm))
	require.NoError(t, json.Unmarshal([]byte(cpmWritten), &fromCpm))

	assert.Equal(t, "Text-CSV-2.06", fromCpanm.Dist)
	assert.Equal(t, "Capture-Tiny-0.48", fromCpm.Dist, "cpm does carry the version suffix on dist, just as cpanm does")
}

// cpanm writes the main module's $VERSION into `version` and the release's distvname into `dist`, so the
// two disagree whenever the module is versioned differently from the release. Name and version must both
// come from `dist`, or the name is the whole distvname and the version never pairs with the packlist
// record for the same install. The cases are the ones reported on the PR, from real cpanm installs.
func TestParseInstallJSON_nameAndVersionFromDist(t *testing.T) {
	tests := []struct {
		name        string
		record      string
		wantName    string
		wantVersion string
	}{
		{
			name:        "module version formatted differently from the release",
			record:      `{"name":"Carp::Assert::More","version":"2.009000","dist":"Carp-Assert-More-2.9.0"}`,
			wantName:    "Carp-Assert-More",
			wantVersion: "2.9.0",
		},
		{
			name:        "module version behind the release",
			record:      `{"name":"Class::Rebirth","version":"1.000","dist":"Class-Rebirth-1.003"}`,
			wantName:    "Class-Rebirth",
			wantVersion: "1.003",
		},
		{
			name:        "TRIAL is a maturity flag, not part of the name or version",
			record:      `{"name":"Try::Tiny","version":"0.26","dist":"Try-Tiny-0.26-TRIAL"}`,
			wantName:    "Try-Tiny",
			wantVersion: "0.26",
		},
		{
			name:        "v-string version stays whole",
			record:      `{"name":"CPAN::02Packages::Search","version":"v1.0.0","dist":"CPAN-02Packages-Search-v1.0.0"}`,
			wantName:    "CPAN-02Packages-Search",
			wantVersion: "v1.0.0",
		},
		{
			name:        "no dist falls back to the PAUSE path",
			record:      `{"name":"LWP","version":"5.836","pathname":"G/GA/GAAS/libwww-perl-5.836.tar.gz"}`,
			wantName:    "libwww-perl",
			wantVersion: "5.836",
		},
		{
			name:        "dist with no version suffix keeps the recorded version",
			record:      `{"name":"URI","version":"5.35","dist":"URI"}`,
			wantName:    "URI",
			wantVersion: "5.35",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs := parseString(t, "install.json", tt.record)
			require.Len(t, pkgs, 1)
			assert.Equal(t, tt.wantName, pkgs[0].Name)
			assert.Equal(t, tt.wantVersion, pkgs[0].Version)
		})
	}
}

func parseString(t *testing.T, location, content string) []pkg.Package {
	t.Helper()

	pkgs, _, err := parseInstallJSON(context.Background(), nil, nil,
		file.NewLocationReadCloser(file.NewLocation(location), io.NopCloser(strings.NewReader(content))))
	require.NoError(t, err)

	return pkgs
}

func TestParseInstallJSON_degrades(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "unparseable json", content: "not json at all\n"},
		{
			// never fall back to splitting the containing directory name
			name:    "missing name and version",
			content: `{"provides":{"URI":{"file":"lib/URI.pm"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromString("URI-5.35/install.json", tt.content).
				Expects(nil, nil).
				TestParser(t, parseInstallJSON)
		})
	}
}
