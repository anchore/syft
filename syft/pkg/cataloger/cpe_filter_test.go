package cataloger

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_jenkinsPluginFilter(t *testing.T) {
	tests := []struct {
		name     string
		cpe      pkg.CPE
		pkg      pkg.Package
		expected bool
	}{
		{
			name: "go case (filter out)",
			cpe:  mustCPE("cpe:2.3:a:name:jenkins:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Type: pkg.JenkinsPluginPkg,
			},
			expected: true,
		},
		{
			name: "ignore jenkins plugins with unique name",
			cpe:  mustCPE("cpe:2.3:a:name:ci-jenkins:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Type: pkg.JenkinsPluginPkg,
			},
			expected: false,
		},
		{
			name: "ignore java packages",
			cpe:  mustCPE("cpe:2.3:a:name:jenkins:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, jenkinsPluginFilter(test.cpe, test.pkg))
		})
	}
}

func Test_jenkinsPackageNameFilter(t *testing.T) {
	tests := []struct {
		name     string
		cpe      pkg.CPE
		pkg      pkg.Package
		expected bool
	}{
		{
			name: "filter out mismatched name (cloudbees vendor)",
			cpe:  mustCPE("cpe:2.3:a:cloudbees:jenkins:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (jenkins vendor)",
			cpe:  mustCPE("cpe:2.3:a:jenkins:jenkins:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (any vendor)",
			cpe:  mustCPE("cpe:2.3:a:*:jenkins:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "ignore packages with the name jenkins",
			cpe:  mustCPE("cpe:2.3:a:*:jenkins:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "jenkins-thing",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "ignore product names that are not exactly 'jenkins'",
			cpe:  mustCPE("cpe:2.3:a:*:jenkins-something-else:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, jenkinsPackageNameFilter(test.cpe, test.pkg))
		})
	}
}

func Test_jiraClientPackageFilter(t *testing.T) {
	tests := []struct {
		name     string
		cpe      pkg.CPE
		pkg      pkg.Package
		expected bool
	}{
		{
			name: "filter out mismatched name (atlassian vendor)",
			cpe:  mustCPE("cpe:2.3:a:atlassian:jira:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "something-client",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (jira vendor)",
			cpe:  mustCPE("cpe:2.3:a:jira:jira:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "something-client",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (any vendor)",
			cpe:  mustCPE("cpe:2.3:a:*:jira:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "something-client",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "ignore package names that do not have 'client'",
			cpe:  mustCPE("cpe:2.3:a:*:jira:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "jira-thing",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "ignore product names that are not exactly 'jira'",
			cpe:  mustCPE("cpe:2.3:a:*:jira-something-else:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "not-j*ra",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, jiraClientPackageFilter(test.cpe, test.pkg))
		})
	}
}
