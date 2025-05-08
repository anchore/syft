package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/cpegenerate/dictionary"
)

func Test_generateIndexedDictionaryJSON(t *testing.T) {
	f, err := os.Open("testdata/official-cpe-dictionary_v2.3.xml")
	require.NoError(t, err)

	// Create a buffer to store the gzipped data in memory
	buf := new(bytes.Buffer)

	w := gzip.NewWriter(buf)
	_, err = io.Copy(w, f)
	require.NoError(t, err)

	// (finalize the gzip stream)
	err = w.Close()
	require.NoError(t, err)

	dictionaryJSON, err := generateIndexedDictionaryJSON(buf)
	assert.NoError(t, err)

	expected, err := os.ReadFile("./testdata/expected-cpe-index.json")
	require.NoError(t, err)

	expectedDictionaryJSONString := string(expected)
	dictionaryJSONString := string(dictionaryJSON)

	if diff := cmp.Diff(expectedDictionaryJSONString, dictionaryJSONString); diff != "" {
		t.Errorf("generateIndexedDictionaryJSON() mismatch (-want +got):\n%s", diff)
	}
}

func Test_addEntryFuncs(t *testing.T) {
	tests := []struct {
		name             string
		addEntryFunc     func(indexed *dictionary.Indexed, ref string, cpeItemName string)
		inputRef         string
		inputCpeItemName string
		expectedIndexed  dictionary.Indexed
	}{
		{
			name:             "addEntryForRustCrate",
			addEntryFunc:     addEntryForRustCrate,
			inputRef:         "https://crates.io/crates/unicycle/versions",
			inputCpeItemName: "cpe:2.3:a:unicycle_project:unicycle:*:*:*:*:*:rust:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemRustCrates: {
						"unicycle": dictionary.NewSet("cpe:2.3:a:unicycle_project:unicycle:*:*:*:*:*:rust:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForJenkinsPluginGitHub",
			addEntryFunc:     addEntryForJenkinsPluginGitHub,
			inputRef:         "https://github.com/jenkinsci/sonarqube-plugin",
			inputCpeItemName: "cpe:2.3:a:sonarsource:sonarqube_scanner:2.7:*:*:*:*:jenkins:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemJenkinsPlugins: {
						"sonarqube": dictionary.NewSet("cpe:2.3:a:sonarsource:sonarqube_scanner:2.7:*:*:*:*:jenkins:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForJenkinsPluginGitHub: not actually a plugin",
			addEntryFunc:     addEntryForJenkinsPluginGitHub,
			inputRef:         "https://github.com/jenkinsci/jenkins",
			inputCpeItemName: "cpe:2.3:a:jenkins:jenkinsci:2.7:*:*:*:*:*:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{},
			},
		},
		{
			name:             "addEntryForJenkinsPlugin",
			addEntryFunc:     addEntryForJenkinsPlugin,
			inputRef:         "https://plugins.jenkins.io/svn-partial-release-mgr/release",
			inputCpeItemName: "cpe:2.3:a:jenkins:subversion_partial_release_manager:1.0.1:*:*:*:*:jenkins:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemJenkinsPlugins: {
						"svn-partial-release-mgr": dictionary.NewSet("cpe:2.3:a:jenkins:subversion_partial_release_manager:1.0.1:*:*:*:*:jenkins:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForPyPIPackage",
			addEntryFunc:     addEntryForPyPIPackage,
			inputRef:         "https://pypi.org/project/vault-cli/#history",
			inputCpeItemName: "cpe:2.3:a:vault-cli_project:vault-cli:*:*:*:*:*:python:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemPyPI: {
						"vault-cli": dictionary.NewSet("cpe:2.3:a:vault-cli_project:vault-cli:*:*:*:*:*:python:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForNativeRubyGem",
			addEntryFunc:     addEntryForNativeRubyGem,
			inputRef:         "https://github.com/ruby/openssl/releases",
			inputCpeItemName: "cpe:2.3:a:ruby-lang:openssl:-:*:*:*:*:ruby:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemRubyGems: {
						"openssl": dictionary.NewSet("cpe:2.3:a:ruby-lang:openssl:-:*:*:*:*:ruby:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForRubyGem: https",
			addEntryFunc:     addEntryForRubyGem,
			inputRef:         "https://rubygems.org/gems/actionview/versions",
			inputCpeItemName: "cpe:2.3:a:action_view_project:action_view:*:*:*:*:*:ruby:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemRubyGems: {
						"actionview": dictionary.NewSet("cpe:2.3:a:action_view_project:action_view:*:*:*:*:*:ruby:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForRubyGem: http",
			addEntryFunc:     addEntryForRubyGem,
			inputRef:         "http://rubygems.org/gems/rbovirt",
			inputCpeItemName: "cpe:2.3:a:amos_benari:rbovirt:*:*:*:*:*:ruby:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemRubyGems: {
						"rbovirt": dictionary.NewSet("cpe:2.3:a:amos_benari:rbovirt:*:*:*:*:*:ruby:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForNPMPackage",
			addEntryFunc:     addEntryForNPMPackage,
			inputRef:         "https://www.npmjs.com/package/@nubosoftware/node-static",
			inputCpeItemName: "cpe:2.3:a:\\@nubosoftware\\/node-static_project:\\@nubosoftware\\/node-static:-:*:*:*:*:node.js:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemNPM: {
						"@nubosoftware/node-static": dictionary.NewSet("cpe:2.3:a:\\@nubosoftware\\/node-static_project:\\@nubosoftware\\/node-static:-:*:*:*:*:node.js:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForPHPPeclPackage",
			addEntryFunc:     addEntryForPHPPeclPackage,
			inputRef:         "https://pecl.php.net/package/imagick/something/something/v4007.0",
			inputCpeItemName: "cpe:2.3:a:php:imagick:*:*:*:*:*:*:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemPHPPecl: {
						"imagick": dictionary.NewSet("cpe:2.3:a:php:imagick:*:*:*:*:*:*:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForPHPPeclPackage http changelog",
			addEntryFunc:     addEntryForPHPPeclPackage,
			inputRef:         "http://pecl.php.net/package-changelog.php?package=memcached&amp;release",
			inputCpeItemName: "cpe:2.3:a:php:memcached:*:*:*:*:*:*:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemPHPPecl: {
						"memcached": dictionary.NewSet("cpe:2.3:a:php:memcached:*:*:*:*:*:*:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForPHPPearPackage",
			addEntryFunc:     addEntryForPHPPearPackage,
			inputRef:         "https://pear.php.net/package/PEAR/download",
			inputCpeItemName: "cpe:2.3:a:php:pear:*:*:*:*:*:*:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemPHPPear: {
						"PEAR": dictionary.NewSet("cpe:2.3:a:php:pear:*:*:*:*:*:*:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForPHPPearPackage http changelog",
			addEntryFunc:     addEntryForPHPPearPackage,
			inputRef:         "http://pear.php.net/package-changelog.php?package=abcdefg&amp;release",
			inputCpeItemName: "cpe:2.3:a:php:abcdefg:*:*:*:*:*:*:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemPHPPear: {
						"abcdefg": dictionary.NewSet("cpe:2.3:a:php:abcdefg:*:*:*:*:*:*:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForPHPComposerPackage",
			addEntryFunc:     addEntryForPHPComposerPackage,
			inputRef:         "https://packagist.org/packages/frappant/frp-form-answers",
			inputCpeItemName: "cpe:2.3:a:frappant:forms_export:*:*:*:*:*:*:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemPHPComposer: {
						"frappant/frp-form-answers": dictionary.NewSet("cpe:2.3:a:frappant:forms_export:*:*:*:*:*:*:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForGoModulePackage",
			addEntryFunc:     addEntryForGoModulePackage,
			inputRef:         "https://pkg.go.dev/github.com/abc/123?whatever=xvgfhfhf",
			inputCpeItemName: "cpe:2.3:a:abc:123:*:*:*:*:*:go:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemGoModules: {
						"github.com/abc/123": dictionary.NewSet("cpe:2.3:a:abc:123:*:*:*:*:*:go:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressPlugin",
			addEntryFunc:     addEntryForWordpressPlugin,
			inputRef:         "https://wordpress.org/plugins/armadillo/releases",
			inputCpeItemName: "cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressPlugins: {
						"armadillo": dictionary.NewSet("cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressPlugin from Trac Browser",
			addEntryFunc:     addEntryForWordpressPlugin,
			inputRef:         "https://plugins.trac.wordpress.org/browser/armadillo/something",
			inputCpeItemName: "cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressPlugins: {
						"armadillo": dictionary.NewSet("cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressPlugin from Trac Log",
			addEntryFunc:     addEntryForWordpressPlugin,
			inputRef:         "https://plugins.trac.wordpress.org/log/armadillo/log",
			inputCpeItemName: "cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressPlugins: {
						"armadillo": dictionary.NewSet("cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressPlugin from GitHub wp-plugins archive",
			addEntryFunc:     addEntryForWordpressPlugin,
			inputRef:         "https://github.com/wp-plugins/armadillo/something",
			inputCpeItemName: "cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressPlugins: {
						"armadillo": dictionary.NewSet("cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressPlugin wordfence",
			addEntryFunc:     addEntryForWordpressPlugin,
			inputRef:         "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/armadillo/skjfhskdjhf/12344",
			inputCpeItemName: "cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressPlugins: {
						"armadillo": dictionary.NewSet("cpe:2.3:a:armadillo:armadillo:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressTheme",
			addEntryFunc:     addEntryForWordpressTheme,
			inputRef:         "https://wordpress.org/themes/basic/releases",
			inputCpeItemName: "cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressThemes: {
						"basic": dictionary.NewSet("cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressTheme from Trac Browser",
			addEntryFunc:     addEntryForWordpressTheme,
			inputRef:         "https://themes.trac.wordpress.org/browser/basic/something",
			inputCpeItemName: "cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressThemes: {
						"basic": dictionary.NewSet("cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressTheme from Trac Log",
			addEntryFunc:     addEntryForWordpressTheme,
			inputRef:         "https://themes.trac.wordpress.org/log/basic/log",
			inputCpeItemName: "cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressThemes: {
						"basic": dictionary.NewSet("cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
		{
			name:             "addEntryForWordpressTheme wordfence",
			addEntryFunc:     addEntryForWordpressTheme,
			inputRef:         "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/basic/skjfhskdjhf/12344",
			inputCpeItemName: "cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*",
			expectedIndexed: dictionary.Indexed{
				EcosystemPackages: map[string]dictionary.Packages{
					dictionary.EcosystemWordpressThemes: {
						"basic": dictionary.NewSet("cpe:2.3:a:basic:basic:1.23:*:*:*:*:wordpress:*:*"),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indexed := &dictionary.Indexed{
				EcosystemPackages: make(map[string]dictionary.Packages),
			}

			tt.addEntryFunc(indexed, tt.inputRef, tt.inputCpeItemName)

			if diff := cmp.Diff(tt.expectedIndexed, *indexed, cmp.AllowUnexported(strset.Set{})); diff != "" {
				t.Errorf("addEntry* mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
