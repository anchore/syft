package cataloger

import (
	"sort"
	"testing"

	"github.com/scylladb/go-set/strset"

	"github.com/scylladb/go-set"

	"github.com/anchore/syft/syft/pkg"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "python language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name:3.2:*:*:*:*:python:*:*",
			},
		},
		{
			name: "javascript language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.JavaScript,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:node.js:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:nodejs:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:node.js:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:nodejs:*:*",
			},
		},
		{
			name: "ruby language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Ruby,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:ruby:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:rails:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:ruby:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:rails:*:*",
			},
		},
		{
			name: "java language",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:maven:*:*",
			},
		},
		{
			name: "java language with groupID",
			p: pkg.Package{
				Name:         "name",
				Version:      "3.2",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "org.sonatype.nexus",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:sonatype:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:sonatype:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:sonatype:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:*:nexus:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:nexus:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:*:nexus:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:sonatype:nexus:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:sonatype:nexus:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:sonatype:nexus:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:nexus:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:nexus:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:nexus:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:name:nexus:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:nexus:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:name:nexus:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:nexus:nexus:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:nexus:nexus:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:nexus:nexus:3.2:*:*:*:*:maven:*:*",
			},
		},
		{
			name: "jenkins package",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
			},
			expected: []string{
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := generatePackageCPEs(test.p)

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
}
