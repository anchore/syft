package cpe

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func Test_disallowJenkinsServerCPEForPluginPackage(t *testing.T) {
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
			assert.Equal(t, test.expected, disallowJenkinsServerCPEForPluginPackage(test.cpe, test.pkg))
		})
	}
}

func Test_disallowJenkinsCPEsNotAssociatedWithJenkins(t *testing.T) {
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
			assert.Equal(t, test.expected, disallowJenkinsCPEsNotAssociatedWithJenkins(test.cpe, test.pkg))
		})
	}
}

func Test_disallowJiraClientServerMismatch(t *testing.T) {
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
			assert.Equal(t, test.expected, disallowJiraClientServerMismatch(test.cpe, test.pkg))
		})
	}
}

func Test_disallowLog4JCVE202144228FalsePositives(t *testing.T) {
	tests := []struct {
		name     string
		cpe      pkg.CPE
		pkg      pkg.Package
		expected bool
	}{
		// filter out
		{
			name: "filter out log4j-api java packages",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-api",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out log4j-slf4j-impl java packages",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-slf4j-impl",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		{
			name: "filter out log4j-to-slf4j java packages",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-to-slf4j",
				Type: pkg.JavaPkg,
			},
			expected: true,
		},
		/// keep
		{
			name: "keep log4j-slf4j-impl for non-java packages",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-slf4j-impl",
				Type: pkg.JenkinsPluginPkg,
			},
			expected: false,
		},
		{
			name: "keep log4j-api non-java packages",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-api",
				Type: pkg.JenkinsPluginPkg,
			},
			expected: false,
		},
		{
			name: "keep log4j-slf4j-impl java packages with wrong vendor",
			cpe:  mustCPE("cpe:2.3:a:NOT-apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-slf4j-impl",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "keep log4j-api java packages with wrong vendor",
			cpe:  mustCPE("cpe:2.3:a:NOT-apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-api",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "keep log4j-slf4j-impl java packages with wrong product",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j-diff:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-slf4j-impl",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "keep log4j-api java packages with wrong product",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j-diff:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j-api",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
		{
			name: "keep log4j java packages",
			cpe:  mustCPE("cpe:2.3:a:apache:log4j:3.2:*:*:*:*:*:*:*"),
			pkg: pkg.Package{
				Name: "log4j",
				Type: pkg.JavaPkg,
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, disallowLog4JCVE202144228FalsePositives(test.cpe, test.pkg))
		})
	}
}
