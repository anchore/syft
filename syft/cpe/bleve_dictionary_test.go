package cpe

import (
	"github.com/anchore/syft/internal/config"
	"io/ioutil"
	"sort"
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/scylladb/go-set"

	"github.com/anchore/syft/syft/pkg"
)

func TestBleveIdentifyPackageCPEs(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "no matching",
			p: pkg.Package{
				Name:     "no-matching",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
				Type:     pkg.DebPkg,
			},
			expected: []string{},
		},
		{
			name: "lower than minimum score",
			p: pkg.Package{
				Name:     "package",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
				Type:     pkg.DebPkg,
			},
			expected: []string{},
		},
		{
			name: "python package",
			p: pkg.Package{
				Name:     "python-package",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:python:python-package:3.2:*:*:*:*:python:*:*",
			},
		},
		{
			name: "node package",
			p: pkg.Package{
				Name:     "nodejs-package",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.JavaScript,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:nodejs:nodejs-package:3.2:*:*:*:*:nodejs:*:*",
				"cpe:2.3:a:nodejs:nodejs-package:3.2:*:*:*:*:node.js:*:*",
			},
		},
		{
			name: "ruby language",
			p: pkg.Package{
				Name:     "ruby-package",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Ruby,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:ruby:ruby-package:3.2:*:*:*:*:rails:*:*",
				"cpe:2.3:a:ruby:ruby-package:3.2:*:*:*:*:ruby:*:*",
			},
		},
		{
			name: "java language",
			p: pkg.Package{
				Name:     "java-package",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.DebPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "com.java",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:java:java-package:3.2:*:*:*:*:java:*:*",
			},
		},
		{
			name: "maven plugin",
			p: pkg.Package{
				Name:     "package-maven-plugin",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.DebPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "com.maven",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:maven:maven-plugin-package:3.2:*:*:*:*:maven:*:*",
			},
		},
		{
			name: "java package with groupId",
			p: pkg.Package{
				Name:         "code-java-package",
				Version:      "3.2",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "org.company",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:company:code-java:3.2:*:*:*:*:java:*:*",
			},
		},
		{
			name: "jenkins package",
			p: pkg.Package{
				Name:     "jenkins-package",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "io.jenkins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:jenkins:jenkins-package:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:jenkins:jenkins-package:3.2:*:*:*:*:cloudbees_jenkins:*:*",
			},
		},
	}

	tempDir, _ := ioutil.TempDir("", "bleve_dictionary_test")
	cpeDictionaryConfig := config.CPEDictionary{
		CacheDir:         tempDir,
		UpdateURL:        "",
		AutoUpdate:       false,
		ValidateChecksum: false,
		MinimumScore:     1,
		SpecificVendors:  []config.SpecificMatch{},
		SpecificProducts: []config.SpecificMatch{},
	}

	curator := NewCurator(cpeDictionaryConfig)
	_ = curator.ImportFrom("test-fixtures/official-cpe-dictionary_v2.3.xml.gz")
	dictionary, _ := curator.GetDictionary()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := dictionary.IdentifyPackageCPEs(test.p)

			expectedCpeSet := set.NewStringSet(test.expected...)
			actualCpeSet := set.NewStringSet()
			for _, a := range actual {
				actualCpeSet.Add(a.BindToFmtString())
			}

			extra := strset.Difference(expectedCpeSet, actualCpeSet).List()
			sort.Strings(extra)
			for _, d := range extra {
				t.Errorf("extra CPE: %+v", d)
			}

			missing := strset.Difference(actualCpeSet, expectedCpeSet).List()
			sort.Strings(missing)
			for _, d := range missing {
				t.Errorf("missing CPE: %+v", d)
			}

		})
	}

	_ = curator.Delete()
}
