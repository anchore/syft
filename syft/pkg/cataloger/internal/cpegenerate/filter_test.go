package cpegenerate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func Test_disallowJenkinsServerCPEForPluginPackage(t *testing.T) {
	tests := []struct {
		name     string
		cpe      cpe.CPE
		pkg      pkg.Package
		expected bool
	}{
		{
			name: "go case (filter out)",
			cpe:  cpe.Must("cpe:2.3:a:name:jenkins:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Type: pkg.JenkinsPluginPkg,
			},
			expected: true,
		},
		{
			name: "ignore jenkins plugins with unique name",
			cpe:  cpe.Must("cpe:2.3:a:name:ci-jenkins:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Type: pkg.JenkinsPluginPkg,
			},
			expected: false,
		},
		{
			name: "ignore java packages",
			cpe:  cpe.Must("cpe:2.3:a:name:jenkins:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, disallowJenkinsServerCPEForPluginPackage(test.cpe.Attributes, test.pkg))
		})
	}
}

func Test_disallowJenkinsCPEsNotAssociatedWithJenkins(t *testing.T) {
	tests := []struct {
		name     string
		cpe      cpe.CPE
		pkg      pkg.Package
		expected bool
	}{
		{
			name: "filter out mismatched name (cloudbees vendor)",
			cpe:  cpe.Must("cpe:2.3:a:cloudbees:jenkins:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (jenkins vendor)",
			cpe:  cpe.Must("cpe:2.3:a:jenkins:jenkins:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (any vendor)",
			cpe:  cpe.Must("cpe:2.3:a:*:jenkins:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "ignore packages with the name jenkins",
			cpe:  cpe.Must("cpe:2.3:a:*:jenkins:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "jenkins-thing",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "ignore product names that are not exactly 'jenkins'",
			cpe:  cpe.Must("cpe:2.3:a:*:jenkins-something-else:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "not-j*nkins",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, disallowJenkinsCPEsNotAssociatedWithJenkins(test.cpe.Attributes, test.pkg))
		})
	}
}

func Test_disallowJiraClientServerMismatch(t *testing.T) {
	tests := []struct {
		name     string
		cpe      cpe.CPE
		pkg      pkg.Package
		expected bool
	}{
		{
			name: "filter out mismatched name (atlassian vendor)",
			cpe:  cpe.Must("cpe:2.3:a:atlassian:jira:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "something-client",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (jira vendor)",
			cpe:  cpe.Must("cpe:2.3:a:jira:jira:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "something-client",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out mismatched name (any vendor)",
			cpe:  cpe.Must("cpe:2.3:a:*:jira:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "something-client",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "ignore package names that do not have 'client'",
			cpe:  cpe.Must("cpe:2.3:a:*:jira:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "jira-thing",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "ignore product names that are not exactly 'jira'",
			cpe:  cpe.Must("cpe:2.3:a:*:jira-something-else:3.2:*:*:*:*:*:*:*", cpe.GeneratedSource),
			pkg: pkg.Package{
				Name: "not-j*ra",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, disallowJiraClientServerMismatch(test.cpe.Attributes, test.pkg))
		})
	}
}
