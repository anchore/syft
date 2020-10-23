package integration

import "github.com/anchore/syft/syft/pkg"

type testCase struct {
	name        string
	pkgType     pkg.Type
	pkgLanguage pkg.Language
	pkgInfo     map[string]string
}

var imageOnlyTestCases = []testCase{
	{
		name:        "find gemspec packages",
		pkgType:     pkg.GemPkg,
		pkgLanguage: pkg.Ruby,
		pkgInfo: map[string]string{
			"bundler": "2.1.4",
		},
	},
	{
		name:        "find npm package",
		pkgType:     pkg.NpmPkg,
		pkgLanguage: pkg.JavaScript,
		pkgInfo: map[string]string{
			"npm": "6.14.6",
		},
	},
	{
		name:        "find python egg & wheel packages",
		pkgType:     pkg.PythonPkg,
		pkgLanguage: pkg.Python,
		pkgInfo: map[string]string{
			"Pygments":     "2.6.1",
			"requests":     "2.22.0",
			"somerequests": "3.22.0",
			"someotherpkg": "3.19.0",
		},
	},
}

var dirOnlyTestCases = []testCase{
	{
		name:        "find gemfile packages",
		pkgType:     pkg.GemPkg,
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
		name:        "find javascript npm packages (yarn.lock & package-lock.json)",
		pkgType:     pkg.NpmPkg,
		pkgLanguage: pkg.JavaScript,
		pkgInfo: map[string]string{
			"@babel/code-frame": "7.10.4",
			"get-stdin":         "8.0.0",
		},
	},
	{
		name:        "find python requirements.txt & setup.py package references",
		pkgType:     pkg.PythonPkg,
		pkgLanguage: pkg.Python,
		pkgInfo: map[string]string{
			// dir specific test cases
			"flask":              "4.0.0",
			"python-dateutil":    "2.8.1",
			"python-swiftclient": "3.8.1",
			"pytz":               "2019.3",
			"jsonschema":         "2.6.0",
			"passlib":            "1.7.2",
			"mypy":               "v0.770",
			// common to image and directory
			"Pygments":     "2.6.1",
			"requests":     "2.22.0",
			"somerequests": "3.22.0",
			"someotherpkg": "3.19.0",
		},
	},
}

var commonTestCases = []testCase{
	{
		name:    "find rpmdb packages",
		pkgType: pkg.RpmPkg,
		pkgInfo: map[string]string{
			"dive": "0.9.2-1",
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
			"joda-time":              "2.9.2",
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

		name:    "find apkdb packages",
		pkgType: pkg.ApkPkg,
		pkgInfo: map[string]string{
			"musl-utils": "1.1.24-r2",
			"libc-utils": "0.7.2-r0",
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
