package ruby

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestParseGemfileLockEntries(t *testing.T) {

	var expectedGems = map[string]string{
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
	}

	fixture, err := os.Open("test-fixtures/Gemfile.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	// TODO: no relationships are under test yet
	actual, _, err := parseGemFileLockEntries(fixture.Name(), fixture)
	if err != nil {
		t.Fatalf("failed to parse gemfile lock: %+v", err)
	}

	if len(actual) != len(expectedGems) {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expectedGems))
	}

	for _, a := range actual {
		expectedVersion, ok := expectedGems[a.Name]
		if !ok {
			t.Errorf("unexpected package found: %s", a.Name)
		}

		if expectedVersion != a.Version {
			t.Errorf("unexpected package version (pkg=%s): %s", a.Name, a.Version)
		}

		if a.Language != pkg.Ruby {
			t.Errorf("bad language (pkg=%+v): %+v", a.Name, a.Language)
		}

		if a.Type != pkg.GemPkg {
			t.Errorf("bad package type (pkg=%+v): %+v", a.Name, a.Type)
		}
	}
}
