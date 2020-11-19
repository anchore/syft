package cataloger

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func must(c pkg.CPE, e error) pkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestGenerate(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []pkg.CPE
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
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:python:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:python:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:python-name:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:python-name:name:3.2:*:*:*:*:python:*:*")),
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
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:node.js:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:nodejs:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:node.js:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:nodejs:*:*")),
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
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:ruby:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:rails:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:ruby:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:rails:*:*")),
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
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:maven:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:maven:*:*")),
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
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:maven:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:maven:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*")),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := generatePackageCPEs(test.p)

			if len(actual) != len(test.expected) {
				for _, e := range actual {
					t.Errorf("   unexpected entry: %+v", e.BindToFmtString())
				}
				t.Fatalf("unexpected number of entries: %d", len(actual))
			}

			for idx, a := range actual {
				e := test.expected[idx]
				if a.BindToFmtString() != e.BindToFmtString() {
					t.Errorf("mismatched entries @ %d:\n\texpected:%+v\n\t  actual:%+v\n", idx, e.BindToFmtString(), a.BindToFmtString())
				}
			}
		})
	}
}
