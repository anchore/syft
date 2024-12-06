package integration

import "github.com/anchore/syft/syft/pkg"

type testCase struct {
	name        string
	pkgType     pkg.Type
	pkgLanguage pkg.Language
	duplicates  int
	pkgInfo     map[string]string
}

var imageOnlyTestCases = []testCase{
	{
		name:        "find gemspec packages",
		pkgType:     pkg.GemPkg,
		pkgLanguage: pkg.Ruby,
		pkgInfo: map[string]string{
			// specifications in the root specification directory
			"bundler": "2.1.4",
			// specifications in named directories
			"unbundler": "3.1.4",
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
			"pygments":     "2.6.1",
			"requests":     "2.22.0",
			"somerequests": "3.22.0",
			"someotherpkg": "3.19.0",
		},
	},
	{
		name:        "find PHP composer installed.json packages",
		pkgType:     pkg.PhpComposerPkg,
		pkgLanguage: pkg.PHP,
		pkgInfo: map[string]string{
			"nikic/fast-route": "v1.3.0",
			"psr/container":    "2.0.2",
			"psr/http-factory": "1.0.1",
		},
	},
	{
		// When the image is build lib overwrites pkgs/lib causing there to only be two packages
		name:    "find apkdb packages",
		pkgType: pkg.ApkPkg,
		pkgInfo: map[string]string{
			"musl-utils": "1.1.24-r2",
			"libc-utils": "0.7.2-r0",
		},
	},
	{
		name:        "find java packages excluding pom.xml", // image scans can not include packages that have yet to be installed
		pkgType:     pkg.JavaPkg,
		pkgLanguage: pkg.Java,
		pkgInfo: map[string]string{
			"example-java-app-maven": "0.1.0",
			"joda-time":              "2.9.2",
		},
	},
	{
		name:        "find R packages",
		pkgType:     pkg.Rpkg,
		pkgLanguage: pkg.R,
		pkgInfo: map[string]string{
			"base": "4.3.0",
		},
	},
	{
		name:        "find dot net executable",
		pkgType:     pkg.DotnetPkg,
		pkgLanguage: pkg.Dotnet,
		pkgInfo: map[string]string{
			"DocuSign.eSign": "6.8.0.0",
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
			"bundler":              "2.1.4",
			"coffee-rails":         "4.0.1",
			"coffee-script":        "2.2.0",
			"coffee-script-source": "1.7.0",
			"erubis":               "2.7.0",
			"execjs":               "2.0.2",
			"google-cloud-errors":  "1.3.0",
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
			"turbolinks":           "3.0.0",
			"tzinfo":               "1.2.0",
			"uglifier":             "2.5.0",
			"unbundler":            "3.1.4",
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
			"pygments":     "2.6.1",
			"requests":     "2.22.0",
			"somerequests": "3.22.0",
			"someotherpkg": "3.19.0",
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
	{
		name:        "find conan packages",
		pkgType:     pkg.ConanPkg,
		pkgLanguage: pkg.CPP,
		pkgInfo: map[string]string{
			"catch2":     "2.13.8",
			"docopt.cpp": "0.6.3",
			"fmt":        "8.1.1",
			"spdlog":     "1.9.2",
			"sdl":        "2.0.20",
			"fltk":       "1.3.8",
		},
	},
	{
		name:        "find rust crates",
		pkgType:     pkg.RustPkg,
		pkgLanguage: pkg.Rust,
		pkgInfo: map[string]string{
			"memchr":        "2.3.3",
			"nom":           "4.2.3",
			"version_check": "0.1.5",
		},
	},
	{
		name:       "find apkdb packages",
		pkgType:    pkg.ApkPkg,
		duplicates: 2, // when the directory is cataloged we have duplicates between lib/ and pkgs/lib
		pkgInfo: map[string]string{
			"musl-utils": "1.1.24-r2",
			"libc-utils": "0.7.2-r0",
		},
	},
	{
		name:        "find php composer package",
		pkgType:     pkg.PhpComposerPkg,
		pkgLanguage: pkg.PHP,
		pkgInfo: map[string]string{
			"adoy/fastcgi-client":       "1.0.2",
			"alcaeus/mongo-php-adapter": "1.1.11",
		},
	},
	{
		name:        "find pubspec lock packages",
		pkgType:     pkg.DartPubPkg,
		pkgLanguage: pkg.Dart,
		pkgInfo: map[string]string{
			"ansicolor":  "1.1.1",
			"archive":    "2.0.13",
			"args":       "1.6.0",
			"key_binder": "1.11.20",
			"ale":        "3.3.0",
			"analyzer":   "0.40.7",
		},
	},
	{
		name:        "find dotnet packages",
		pkgType:     pkg.DotnetPkg,
		pkgLanguage: pkg.Dotnet,
		pkgInfo: map[string]string{
			"AWSSDK.Core": "3.7.10.6",
			"Microsoft.Extensions.DependencyInjection":              "6.0.0",
			"Microsoft.Extensions.DependencyInjection.Abstractions": "6.0.0",
			"Microsoft.Extensions.Logging":                          "6.0.0",
			"Microsoft.Extensions.Logging.Abstractions":             "6.0.0",
			"Microsoft.Extensions.Options":                          "6.0.0",
			"Microsoft.Extensions.Primitives":                       "6.0.0",
			"Newtonsoft.Json":                                       "13.0.1",
			"Serilog":                                               "2.10.0",
			"Serilog.Sinks.Console":                                 "4.0.1",
			"System.Diagnostics.DiagnosticSource":                   "6.0.0",
			"System.Runtime.CompilerServices.Unsafe":                "6.0.0",
			"TestCommon":                                            "1.0.0",
			"TestLibrary":                                           "1.0.0",
		},
	},
	{
		name:        "find java packages including pom.xml", // directory scans can include packages that have yet to be installed
		pkgType:     pkg.JavaPkg,
		pkgLanguage: pkg.Java,
		duplicates:  2, // joda-time and example-java-app-maven are included in both pom.xml AND the .jar collection
		pkgInfo: map[string]string{
			"example-java-app-maven": "0.1.0",
			"joda-time":              "2.9.2",
			"junit":                  "4.12",
		},
	},
	{
		name:        "find cocoapods packages",
		pkgType:     pkg.CocoapodsPkg,
		pkgLanguage: pkg.Swift,
		pkgInfo: map[string]string{
			"GlossButtonNode":                        "3.1.2",
			"PINCache":                               "3.0.3",
			"PINCache/Arc-exception-safe":            "3.0.3",
			"PINCache/Core":                          "3.0.3",
			"PINOperation":                           "1.2.1",
			"PINRemoteImage/Core":                    "3.0.3",
			"PINRemoteImage/iOS":                     "3.0.3",
			"PINRemoteImage/PINCache":                "3.0.3",
			"Reveal-SDK":                             "33",
			"SwiftGen":                               "6.5.1",
			"Texture":                                "3.1.0",
			"Texture/AssetsLibrary":                  "3.1.0",
			"Texture/Core":                           "3.1.0",
			"Texture/MapKit":                         "3.1.0",
			"Texture/Photos":                         "3.1.0",
			"Texture/PINRemoteImage":                 "3.1.0",
			"Texture/Video":                          "3.1.0",
			"TextureSwiftSupport":                    "3.13.0",
			"TextureSwiftSupport/Components":         "3.13.0",
			"TextureSwiftSupport/Experiments":        "3.13.0",
			"TextureSwiftSupport/Extensions":         "3.13.0",
			"TextureSwiftSupport/LayoutSpecBuilders": "3.13.0",
			"TinyConstraints":                        "4.0.2",
		},
	},
	{
		name:        "find hackage packages",
		pkgType:     pkg.HackagePkg,
		pkgLanguage: pkg.Haskell,
		pkgInfo: map[string]string{
			"Cabal":                    "3.2.1.0",
			"Diff":                     "0.4.1",
			"HTTP":                     "4000.3.16",
			"HUnit":                    "1.6.2.0",
			"OneTuple":                 "0.3.1",
			"Only":                     "0.1",
			"PyF":                      "0.10.2.0",
			"QuickCheck":               "2.14.2",
			"RSA":                      "2.4.1",
			"SHA":                      "1.6.4.4",
			"Spock":                    "0.14.0.0",
			"ShellCheck":               "0.8.0",
			"colourista":               "0.1.0.1",
			"language-docker":          "11.0.0",
			"spdx":                     "1.0.0.2",
			"hspec":                    "2.9.4",
			"hspec-core":               "2.9.4",
			"hspec-discover":           "2.9.4",
			"stm":                      "2.5.0.2",
			"configurator-pg":          "0.2.6",
			"hasql-dynamic-statements": "0.3.1.1",
			"hasql-implicits":          "0.1.0.4",
			"hasql-pool":               "0.5.2.2",
			"lens-aeson":               "1.1.3",
			"optparse-applicative":     "0.16.1.0",
			"protolude":                "0.3.2",
			"ptr":                      "0.16.8.2",
		},
	},
	{
		name:        "find hex packages",
		pkgType:     pkg.HexPkg,
		pkgLanguage: pkg.Elixir + "," + pkg.Erlang,
		pkgInfo: map[string]string{
			// elixir
			"castore":          "0.1.17",
			"connection":       "1.1.0",
			"cowboy":           "2.9.0",
			"cowboy_telemetry": "0.4.0",
			"cowlib":           "2.11.0",
			"db_connection":    "2.4.2",
			"decimal":          "2.0.0",
			"earmark_parser":   "1.4.25",
			"ecto":             "3.8.1",
			"ecto_sql":         "3.8.1",
			"esbuild":          "0.5.0",
			"ex_doc":           "0.28.4",
			"gettext":          "0.19.1",
			"hpax":             "0.1.1",
			"jason":            "1.3.0",

			// erlang
			"certifi":             "2.9.0",
			"idna":                "6.1.1",
			"metrics":             "1.0.1",
			"mimerl":              "1.2.0",
			"parse_trans":         "3.3.1",
			"ssl_verify_fun":      "1.1.6",
			"unicode_util_compat": "0.7.0",
		},
	},
	{
		name:        "find ErLang OTP applications",
		pkgType:     pkg.ErlangOTPPkg,
		pkgLanguage: pkg.Erlang,
		pkgInfo: map[string]string{
			"accept": "0.3.5",
		},
	},
	{
		name:        "find swift package manager packages",
		pkgType:     pkg.SwiftPkg,
		pkgLanguage: pkg.Swift,
		pkgInfo: map[string]string{
			"swift-algorithms":       "1.0.0",
			"swift-async-algorithms": "0.1.0",
			"swift-atomics":          "1.1.0",
			"swift-collections":      "1.0.4",
			"swift-numerics":         "1.0.2",
		},
	},
	{
		name:        "find swipl pack package manager packages",
		pkgType:     pkg.SwiplPackPkg,
		pkgLanguage: pkg.Swipl,
		pkgInfo: map[string]string{
			"hdt": "0.5.2",
		},
	},
	{
		name:    "find github action packages (from usage in workflow files and composite actions)",
		pkgType: pkg.GithubActionPkg,
		pkgInfo: map[string]string{
			"actions/checkout": "v4",
		},
	},
	{
		name:    "find github shared workflow calls (from usage in workflow files)",
		pkgType: pkg.GithubActionWorkflowPkg,
		pkgInfo: map[string]string{
			"octo-org/this-repo/.github/workflows/workflow-1.yml": "172239021f7ba04fe7327647b213799853a9eb89",
		},
	},
	{
		name:        "find opam package",
		pkgType:     pkg.OpamPkg,
		pkgLanguage: pkg.OCaml,
		pkgInfo: map[string]string{
			"ocaml-base-compiler": "4.14.0",
		},
	},
}

var commonTestCases = []testCase{
	{
		name:    "find alpm packages",
		pkgType: pkg.AlpmPkg,
		pkgInfo: map[string]string{
			"pacman": "6.0.1-5",
		},
	},
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
			"apt":     "1.8.2",
			"dash":    "0.5.8-2.4",
			"netbase": "5.4",
		},
	},
	{
		name:    "find portage packages",
		pkgType: pkg.PortagePkg,
		pkgInfo: map[string]string{
			"app-containers/skopeo": "1.5.1",
		},
	},

	{
		name:        "find jenkins plugins",
		pkgType:     pkg.JenkinsPluginPkg,
		pkgLanguage: pkg.Java,
		duplicates:  1, // there is a "example-jenkins-plugin" HPI, and nested within that a JAR of the same name
		pkgInfo: map[string]string{
			"example-jenkins-plugin": "1.0-SNAPSHOT",
		},
	},
	{
		name:    "find nix store packages",
		pkgType: pkg.NixPkg,
		pkgInfo: map[string]string{
			"glibc": "2.34-210",
		},
	},
	{
		name:        "find wordpress plugins",
		pkgType:     pkg.WordpressPluginPkg,
		pkgLanguage: pkg.PHP,
		pkgInfo: map[string]string{
			"Akismet Anti-spam: Spam Protection": "5.3",
		},
	},
	{
		name:        "find php pecl package",
		pkgType:     pkg.PhpPeclPkg,
		pkgLanguage: pkg.PHP,
		pkgInfo: map[string]string{
			"memcached": "3.2.0",
		},
	},
	{
		name:        "find lua rock package",
		pkgType:     pkg.LuaRocksPkg,
		pkgLanguage: pkg.Lua,
		pkgInfo: map[string]string{
			"kong": "3.7.0-0",
		},
	},
}
