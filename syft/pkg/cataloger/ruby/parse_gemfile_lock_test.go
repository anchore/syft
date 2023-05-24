package ruby

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseGemfileLockEntries(t *testing.T) {
	fixture := "test-fixtures/Gemfile.lock"
	locations := file.NewLocationSet(file.NewLocation(fixture))
	var expectedPkgs = []pkg.Package{
		{Name: "actionmailer", Version: "4.1.1", PURL: "pkg:gem/actionmailer@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "actionpack", Version: "4.1.1", PURL: "pkg:gem/actionpack@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "actionview", Version: "4.1.1", PURL: "pkg:gem/actionview@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "activemodel", Version: "4.1.1", PURL: "pkg:gem/activemodel@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "activerecord", Version: "4.1.1", PURL: "pkg:gem/activerecord@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "activesupport", Version: "4.1.1", PURL: "pkg:gem/activesupport@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "arel", Version: "5.0.1.20140414130214", PURL: "pkg:gem/arel@5.0.1.20140414130214", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "bootstrap-sass", Version: "3.1.1.1", PURL: "pkg:gem/bootstrap-sass@3.1.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "builder", Version: "3.2.2", PURL: "pkg:gem/builder@3.2.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "coffee-rails", Version: "4.0.1", PURL: "pkg:gem/coffee-rails@4.0.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "coffee-script", Version: "2.2.0", PURL: "pkg:gem/coffee-script@2.2.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "coffee-script-source", Version: "1.7.0", PURL: "pkg:gem/coffee-script-source@1.7.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "erubis", Version: "2.7.0", PURL: "pkg:gem/erubis@2.7.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "execjs", Version: "2.0.2", PURL: "pkg:gem/execjs@2.0.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "google-cloud-errors", Version: "1.3.0", PURL: "pkg:gem/google-cloud-errors@1.3.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "hike", Version: "1.2.3", PURL: "pkg:gem/hike@1.2.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "i18n", Version: "0.6.9", PURL: "pkg:gem/i18n@0.6.9", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "jbuilder", Version: "2.0.7", PURL: "pkg:gem/jbuilder@2.0.7", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "jquery-rails", Version: "3.1.0", PURL: "pkg:gem/jquery-rails@3.1.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "json", Version: "1.8.1", PURL: "pkg:gem/json@1.8.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "kgio", Version: "2.9.2", PURL: "pkg:gem/kgio@2.9.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "libv8", Version: "3.16.14.3", PURL: "pkg:gem/libv8@3.16.14.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "mail", Version: "2.5.4", PURL: "pkg:gem/mail@2.5.4", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "mime-types", Version: "1.25.1", PURL: "pkg:gem/mime-types@1.25.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "minitest", Version: "5.3.4", PURL: "pkg:gem/minitest@5.3.4", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "multi_json", Version: "1.10.1", PURL: "pkg:gem/multi_json@1.10.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "mysql2", Version: "0.3.16", PURL: "pkg:gem/mysql2@0.3.16", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "polyglot", Version: "0.3.4", PURL: "pkg:gem/polyglot@0.3.4", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rack", Version: "1.5.2", PURL: "pkg:gem/rack@1.5.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rack-test", Version: "0.6.2", PURL: "pkg:gem/rack-test@0.6.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rails", Version: "4.1.1", PURL: "pkg:gem/rails@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "railties", Version: "4.1.1", PURL: "pkg:gem/railties@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "raindrops", Version: "0.13.0", PURL: "pkg:gem/raindrops@0.13.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rake", Version: "10.3.2", PURL: "pkg:gem/rake@10.3.2", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "rdoc", Version: "4.1.1", PURL: "pkg:gem/rdoc@4.1.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "ref", Version: "1.0.5", PURL: "pkg:gem/ref@1.0.5", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sass", Version: "3.2.19", PURL: "pkg:gem/sass@3.2.19", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sass-rails", Version: "4.0.3", PURL: "pkg:gem/sass-rails@4.0.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sdoc", Version: "0.4.0", PURL: "pkg:gem/sdoc@0.4.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "spring", Version: "1.1.3", PURL: "pkg:gem/spring@1.1.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sprockets", Version: "2.11.0", PURL: "pkg:gem/sprockets@2.11.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sprockets-rails", Version: "2.1.3", PURL: "pkg:gem/sprockets-rails@2.1.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "sqlite3", Version: "1.3.9", PURL: "pkg:gem/sqlite3@1.3.9", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "therubyracer", Version: "0.12.1", PURL: "pkg:gem/therubyracer@0.12.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "thor", Version: "0.19.1", PURL: "pkg:gem/thor@0.19.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "thread_safe", Version: "0.3.3", PURL: "pkg:gem/thread_safe@0.3.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "tilt", Version: "1.4.1", PURL: "pkg:gem/tilt@1.4.1", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "treetop", Version: "1.4.15", PURL: "pkg:gem/treetop@1.4.15", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "turbolinks", Version: "3.0.0", PURL: "pkg:gem/turbolinks@3.0.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "tzinfo", Version: "1.2.0", PURL: "pkg:gem/tzinfo@1.2.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "uglifier", Version: "2.5.0", PURL: "pkg:gem/uglifier@2.5.0", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
		{Name: "unicorn", Version: "4.8.3", PURL: "pkg:gem/unicorn@4.8.3", Locations: locations, Language: pkg.Ruby, Type: pkg.GemPkg},
	}

	pkgtest.TestFileParser(t, fixture, parseGemFileLockEntries, expectedPkgs, nil)
}
