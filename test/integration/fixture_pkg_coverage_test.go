// +build integration

package integration

import (
	"testing"

	"github.com/anchore/imgbom/imgbom"

	"github.com/anchore/imgbom/internal"

	"github.com/anchore/go-testutils"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
)

var cases = []struct {
	name        string
	pkgType     pkg.Type
	pkgLanguage pkg.Language
	pkgInfo     map[string]string
}{
	{
		name:    "find rpmdb packages",
		pkgType: pkg.RpmPkg,
		pkgInfo: map[string]string{
			"dive": "0.9.2",
		},
	},
	{
		name:    "find dpkg packages",
		pkgType: pkg.DebPkg,
		pkgInfo: map[string]string{
			"apt": "1.8.2",
		},
	},
	{
		name:        "find java packages",
		pkgType:     pkg.JavaPkg,
		pkgLanguage: pkg.Java,
		pkgInfo: map[string]string{
			"example-java-app-maven": "0.1.0",
			"example-jenkins-plugin": "1.0-SNAPSHOT", // the jenkins HPI file has a nested JAR of the same name
		},
	},
	{
		name:        "find jenkins plugins",
		pkgType:     pkg.JenkinsPluginPkg,
		pkgLanguage: pkg.Java,
		pkgInfo: map[string]string{
			"example-jenkins-plugin": "1.0-SNAPSHOT",
		},
	},
	{
		name:        "find python wheel packages",
		pkgType:     pkg.WheelPkg,
		pkgLanguage: pkg.Python,
		pkgInfo: map[string]string{
			"Pygments": "2.6.1",
		},
	},
	{
		name:        "find javascript npm packages",
		pkgType:     pkg.NpmPkg,
		pkgLanguage: pkg.JavaScript,
		pkgInfo: map[string]string{
			"get-stdin": "8.0.0",
		},
	},
	{
		name:        "find python egg packages",
		pkgType:     pkg.EggPkg,
		pkgLanguage: pkg.Python,
		pkgInfo: map[string]string{
			"requests": "2.22.0",
		},
	},
	{
		name:        "find python packages",
		pkgType:     pkg.PythonRequirementsPkg,
		pkgLanguage: pkg.Python,
		pkgInfo: map[string]string{
			"flask": "4.0.0",
		},
	},
	{
		name:        "find bundler packages",
		pkgType:     pkg.BundlerPkg,
		pkgLanguage: pkg.Ruby,
		pkgInfo: map[string]string{
			"actionmailer":         "4.1.1",
			"actionpack":           "4.1.1",
			"actionview":           "4.1.1",
			"activemodel":          "4.1.1",
			"activerecord":         "4.1.1",
			"activesupport":        "4.1.1",
			"arel":                 "5.0.1.20140414130214",
			"bootstrap-sass":       "3.1.1.1",
			"builder":              "3.2.2",
			"coffee-rails":         "4.0.1",
			"coffee-script":        "2.2.0",
			"coffee-script-source": "1.7.0",
			"erubis":               "2.7.0",
			"execjs":               "2.0.2",
			"hike":                 "1.2.3",
			"i18n":                 "0.6.9",
			"jbuilder":             "2.0.7",
			"jquery-rails":         "3.1.0",
			"json":                 "1.8.1",
			"kgio":                 "2.9.2",
			"libv8":                "3.16.14.3",
			"mail":                 "2.5.4",
			"mime-types":           "1.25.1",
			"minitest":             "5.3.4",
			"multi_json":           "1.10.1",
			"mysql2":               "0.3.16",
			"polyglot":             "0.3.4",
			"rack":                 "1.5.2",
			"rack-test":            "0.6.2",
			"rails":                "4.1.1",
			"railties":             "4.1.1",
			"raindrops":            "0.13.0",
			"rake":                 "10.3.2",
			"rdoc":                 "4.1.1",
			"ref":                  "1.0.5",
			"sass":                 "3.2.19",
			"sass-rails":           "4.0.3",
			"sdoc":                 "0.4.0",
			"spring":               "1.1.3",
			"sprockets":            "2.11.0",
			"sprockets-rails":      "2.1.3",
			"sqlite3":              "1.3.9",
			"therubyracer":         "0.12.1",
			"thor":                 "0.19.1",
			"thread_safe":          "0.3.3",
			"tilt":                 "1.4.1",
			"treetop":              "1.4.15",
			"turbolinks":           "2.2.2",
			"tzinfo":               "1.2.0",
			"uglifier":             "2.5.0",
			"unicorn":              "4.8.3",
		},
	},
	{
		name:        "find golang modules",
		pkgType:     pkg.GoModulePkg,
		pkgLanguage: pkg.Go,
		pkgInfo: map[string]string{
			"github.com/bmatcuk/doublestar": "v1.3.1",
		},
	},
}

func TestPkgCoverageImage(t *testing.T) {
	fixtureImageName := "image-pkg-coverage"
	_, cleanup := testutils.GetFixtureImage(t, "docker-archive", fixtureImageName)
	tarPath := testutils.GetFixtureImageTarPath(t, fixtureImageName)
	defer cleanup()

	catalog, _, _, err := imgbom.Catalog("docker-archive://"+tarPath, scope.AllLayersScope)
	if err != nil {
		t.Fatalf("failed to catalog image: %+v", err)
	}

	observedLanguages := internal.NewStringSet()
	definedLanguages := internal.NewStringSet()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	observedPkgs := internal.NewStringSet()
	definedPkgs := internal.NewStringSet()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(p.String())
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgCount := 0

			for a := range catalog.Enumerate(c.pkgType) {

				observedLanguages.Add(a.Language.String())
				observedPkgs.Add(a.Type.String())

				expectedVersion, ok := c.pkgInfo[a.Name]
				if !ok {
					t.Errorf("unexpected package found: %s", a.Name)
				}

				if expectedVersion != a.Version {
					t.Errorf("unexpected package version (pkg=%s): %s, expected: %s", a.Name, a.Version, expectedVersion)
				}

				if a.Language != c.pkgLanguage {
					t.Errorf("bad language (pkg=%+v): %+v", a.Name, a.Language)
				}

				if a.Type != c.pkgType {
					t.Errorf("bad package type (pkg=%+v): %+v", a.Name, a.Type)
				}
				pkgCount++
			}

			if pkgCount != len(c.pkgInfo) {
				for a := range catalog.Enumerate(c.pkgType) {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", pkgCount, len(c.pkgInfo))
			}

		})
	}

	observedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.UnknownLanguage.String())
	observedPkgs.Remove(pkg.UnknownPkg.String())
	definedPkgs.Remove(pkg.UnknownPkg.String())

	// ensure that integration test cases stay in sync with the available catalogers
	if len(observedLanguages) < len(definedLanguages) {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", len(definedLanguages), len(observedLanguages))
	}

	if len(observedPkgs) < len(definedPkgs) {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", len(definedPkgs), len(observedPkgs))
	}
}

func TestPkgCoverageDirectory(t *testing.T) {
	catalog, _, _, err := imgbom.Catalog("dir://test-fixtures/image-pkg-coverage", scope.AllLayersScope)

	if err != nil {
		t.Errorf("unable to create scope from dir: %+v", err)
	}

	observedLanguages := internal.NewStringSet()
	definedLanguages := internal.NewStringSet()
	for _, l := range pkg.AllLanguages {
		definedLanguages.Add(l.String())
	}

	observedPkgs := internal.NewStringSet()
	definedPkgs := internal.NewStringSet()
	for _, p := range pkg.AllPkgs {
		definedPkgs.Add(p.String())
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkgCount := 0

			for a := range catalog.Enumerate(c.pkgType) {

				observedLanguages.Add(a.Language.String())
				observedPkgs.Add(a.Type.String())

				expectedVersion, ok := c.pkgInfo[a.Name]
				if !ok {
					t.Errorf("unexpected package found: %s", a.Name)
				}

				if expectedVersion != a.Version {
					t.Errorf("unexpected package version (pkg=%s): %s", a.Name, a.Version)
				}

				if a.Language != c.pkgLanguage {
					t.Errorf("bad language (pkg=%+v): %+v", a.Name, a.Language)
				}

				if a.Type != c.pkgType {
					t.Errorf("bad package type (pkg=%+v): %+v", a.Name, a.Type)
				}
				pkgCount++
			}

			if pkgCount != len(c.pkgInfo) {
				for a := range catalog.Enumerate(c.pkgType) {
					t.Log("   ", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", pkgCount, len(c.pkgInfo))
			}

		})
	}

	observedLanguages.Remove(pkg.UnknownLanguage.String())
	definedLanguages.Remove(pkg.UnknownLanguage.String())
	observedPkgs.Remove(pkg.UnknownPkg.String())
	definedPkgs.Remove(pkg.UnknownPkg.String())

	// ensure that integration test cases stay in sync with the available catalogers
	if len(observedLanguages) < len(definedLanguages) {
		t.Errorf("language coverage incomplete (languages=%d, coverage=%d)", len(definedLanguages), len(observedLanguages))
	}

	if len(observedPkgs) < len(definedPkgs) {
		t.Errorf("package coverage incomplete (packages=%d, coverage=%d)", len(definedPkgs), len(observedPkgs))
	}
}
