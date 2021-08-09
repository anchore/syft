package cataloger

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func TestGeneratePackageCPEs(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "hyphen replacement",
			p: pkg.Package{
				Name:     "name-part",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Python,
				Type:     pkg.DebPkg,
			},
			expected: []string{
				"cpe:2.3:a:name-part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name-part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name_part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name_part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name-part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name_part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name-part:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name_part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name-part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name-part:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:python_name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name_part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name_part:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name_part:python_name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name-part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name-part:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:python_name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name_part:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name_part:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name_part:python_name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python_name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python_name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python_name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:name_part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python_name_part:3.2:*:*:*:*:python:*:*",
			},
		},
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
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python-name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:python_name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python-name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:python_name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python-name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:python_name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python-name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python:python_name:3.2:*:*:*:*:python:*:*",
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
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:ruby:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:rails:*:*",
				"cpe:2.3:a:ruby-lang:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby-lang:name:3.2:*:*:*:*:rails:*:*",
				"cpe:2.3:a:ruby-lang:name:3.2:*:*:*:*:ruby:*:*",
				"cpe:2.3:a:ruby:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby:name:3.2:*:*:*:*:rails:*:*",
				"cpe:2.3:a:ruby:name:3.2:*:*:*:*:ruby:*:*",
				"cpe:2.3:a:ruby_lang:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:ruby_lang:name:3.2:*:*:*:*:rails:*:*",
				"cpe:2.3:a:ruby_lang:name:3.2:*:*:*:*:ruby:*:*",
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
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:sonatype:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:sonatype:name:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:sonatype:name:3.2:*:*:*:*:maven:*:*",
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
			name: "jenkins package identified via pkg type",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
			},
		},
		{
			name: "cloudbees jenkins package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "com.cloudbees.jenkins.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:jenkins:name:3.2:*:*:*:*:jenkins:*:*",
			},
		},
		{
			name: "jenkins.io package identified via groupId prefix",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "io.jenkins.plugins.name.something",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:something:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:something:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:name:something:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:something:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:something:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:something:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:something:something:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:something:something:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:something:something:3.2:*:*:*:*:jenkins:*:*",
			},
		},
		{
			name: "jenkins.io package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "io.jenkins.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
			},
		},
		{
			name: "jenkins-ci.io package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "io.jenkins-ci.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
			},
		},
		{
			name: "jenkins-ci.org package identified via groupId",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "org.jenkins-ci.plugins",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
			},
		},
		{
			name: "jira-atlassian filtering",
			p: pkg.Package{
				Name:         "jira_client_core",
				Version:      "3.2",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID:    "org.atlassian.jira",
						ArtifactID: "jira_client_core",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:atlassian:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira_client_core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:atlassian:jira_client_core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira:jira_client_core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira:jira_client_core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira_client_core:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client_core:jira:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira_client_core:jira:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira_client_core:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client_core:jira_client_core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira_client_core:jira_client_core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:atlassian:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:atlassian:jira-client-core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:atlassian:jira-client-core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira-client-core:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client-core:jira-client-core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira-client-core:jira-client-core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira-client-core:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client-core:jira:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira-client-core:jira:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira-client-core:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client-core:jira_client_core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira-client-core:jira_client_core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira-client:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client:jira-client-core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira-client:jira-client-core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira-client:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client:jira:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira-client:jira:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira-client:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira-client:jira_client_core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira-client:jira_client_core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira:jira-client-core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira:jira-client-core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira_client:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client:jira-client-core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira_client:jira-client-core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira_client:jira:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client:jira:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira_client:jira:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira_client:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client:jira_client_core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira_client:jira_client_core:3.2:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jira_client_core:jira-client-core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:jira_client_core:jira-client-core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:jira_client_core:jira-client-core:3.2:*:*:*:*:maven:*:*",
			},
		},
		{
			name: "jenkins filtering",
			p: pkg.Package{
				Name:         "cloudbees-installation-manager",
				Version:      "2.89.0.33",
				FoundBy:      "some-analyzer",
				Language:     pkg.Java,
				Type:         pkg.JavaPkg,
				MetadataType: pkg.JavaMetadataType,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID:    "com.cloudbees.jenkins.modules",
						ArtifactID: "cloudbees-installation-manager",
					},
				},
			},
			expected: []string{
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jenkins:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:jenkins:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jenkins:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:jenkins:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees-installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees_installation:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:modules:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:modules:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:modules:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:modules:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:modules:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:modules:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
			},
		},
		{
			name: "go product and vendor candidates are wired up",
			p: pkg.Package{
				Name:     "github.com/someone/something",
				Version:  "3.2",
				FoundBy:  "go-cataloger",
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
			},
			expected: []string{
				"cpe:2.3:a:someone:something:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:someone:something:3.2:*:*:*:*:go:*:*",
				"cpe:2.3:a:someone:something:3.2:*:*:*:*:golang:*:*",
			},
		},
		{
			name: "generate no CPEs for indeterminate golang package name",
			p: pkg.Package{
				Name:     "github.com/what",
				Version:  "3.2",
				FoundBy:  "go-cataloger",
				Language: pkg.Go,
				Type:     pkg.GoModulePkg,
			},
			expected: []string{},
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
			if len(extra) > 0 {
				t.Errorf("found extra CPEs:")
			}
			for _, d := range extra {
				fmt.Printf("   %q,\n", d)
			}

			missing := strset.Difference(actualCpeSet, expectedCpeSet).List()
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Errorf("missing CPEs:")
			}
			for _, d := range missing {
				fmt.Printf("   %q,\n", d)
			}
		})
	}
}

func TestCandidateProducts(t *testing.T) {
	tests := []struct {
		p        pkg.Package
		expected []string
	}{
		{
			p: pkg.Package{
				Name: "springframework",
				Type: pkg.JavaPkg,
			},
			expected: []string{"spring_framework", "springsource_spring_framework" /* <-- known good names | default guess --> */, "springframework"},
		},
		{
			p: pkg.Package{
				Name:     "some-java-package-with-group-id",
				Type:     pkg.JavaPkg,
				Language: pkg.Java,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "com.apple.itunes",
					},
				},
			},
			expected: []string{"itunes", "some-java-package-with-group-id", "some_java_package_with_group_id"},
		},
		{
			p: pkg.Package{
				Name:     "some-jenkins-plugin",
				Type:     pkg.JenkinsPluginPkg,
				Language: pkg.Java,
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "com.cloudbees.jenkins.plugins",
					},
				},
			},
			expected: []string{"some-jenkins-plugin", "some_jenkins_plugin", "jenkins"},
		},
		{
			p: pkg.Package{
				Name: "handlebars.js",
				Type: pkg.NpmPkg,
			},
			expected: []string{"handlebars" /* <-- known good names | default guess --> */, "handlebars.js"},
		},
		{
			p: pkg.Package{
				Name: "RedCloth",
				Type: pkg.GemPkg,
			},
			expected: []string{"redcloth_library" /* <-- known good names | default guess --> */, "RedCloth"},
		},
		{
			p: pkg.Package{
				Name: "python-rrdtool",
				Type: pkg.PythonPkg,
			},
			expected: []string{"rrdtool" /* <-- known good names | default guess --> */, "python-rrdtool", "python_rrdtool"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v %+v", test.p, test.expected), func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, candidateProducts(test.p))
		})
	}
}

func TestCandidateTargetSoftwareAttrs(t *testing.T) {
	cases := []struct {
		name     string
		p        pkg.Package
		expected []string
	}{
		{
			name: "Java",
			p: pkg.Package{
				Language: pkg.Java,
				Type:     pkg.JavaPkg,
			},
			expected: []string{"java", "maven"},
		},
		{
			name: "Jenkins plugin",
			p: pkg.Package{
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
			},
			expected: []string{"jenkins", "cloudbees_jenkins"},
		},
		{
			name: "JavaScript",
			p: pkg.Package{
				Language: pkg.JavaScript,
			},
			expected: []string{"node.js", "nodejs"},
		},
		{
			name: "Ruby",
			p: pkg.Package{
				Language: pkg.Ruby,
			},
			expected: []string{"ruby", "rails"},
		},
		{
			name: "Python",
			p: pkg.Package{
				Language: pkg.Python,
			},
			expected: []string{"python"},
		},
		{
			name: "Other language",
			p: pkg.Package{
				Language: pkg.Rust,
			},
			expected: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual := candidateTargetSoftwareAttrs(tc.p)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestCandidateProductForGo(t *testing.T) {
	tests := []struct {
		pkg      string
		expected string
	}{
		{
			pkg:      "github.com/someone/something",
			expected: "something",
		},
		{
			pkg:      "golang.org/x/xerrors",
			expected: "x/xerrors",
		},
		{
			pkg:      "gopkg.in/yaml.v2",
			expected: "yaml.v2",
		},
		{
			pkg:      "place",
			expected: "",
		},
		{
			pkg:      "place.com/",
			expected: "",
		},
		{
			pkg:      "place.com/someone-or-thing",
			expected: "",
		},
		{
			pkg:      "google.golang.org/genproto/googleapis/rpc/status",
			expected: "genproto",
		},
		{
			pkg:      "github.com/someone/something/long/package/name",
			expected: "something",
		},
	}

	for _, test := range tests {
		t.Run(test.pkg, func(t *testing.T) {
			assert.Equal(t, test.expected, candidateProductForGo(test.pkg))
		})
	}
}

func TestCandidateVendorForGo(t *testing.T) {
	tests := []struct {
		pkg      string
		expected string
	}{
		{
			pkg:      "github.com/someone/something",
			expected: "someone",
		},
		{
			pkg:      "golang.org/x/xerrors",
			expected: "golang",
		},
		{
			pkg:      "gopkg.in/yaml.v2",
			expected: "",
		},
		{
			pkg:      "place",
			expected: "",
		},
		{
			pkg:      "place.com/",
			expected: "",
		},
		{
			pkg:      "place.com/someone-or-thing",
			expected: "",
		},
		{
			pkg:      "google.golang.org/genproto/googleapis/rpc/status",
			expected: "google",
		},
		{
			pkg:      "github.com/someone/something/long/package/name",
			expected: "someone",
		},
	}

	for _, test := range tests {
		t.Run(test.pkg, func(t *testing.T) {
			assert.Equal(t, test.expected, candidateVendorForGo(test.pkg))
		})
	}
}

func Test_generateSubSelections(t *testing.T) {
	tests := []struct {
		field    string
		expected []string
	}{
		{
			field:    "jenkins",
			expected: []string{"jenkins"},
		},
		{
			field:    "jenkins-ci",
			expected: []string{"jenkins", "jenkins-ci"},
		},
		{
			field:    "jenkins--ci",
			expected: []string{"jenkins", "jenkins-ci"},
		},
		{
			field:    "jenkins_ci_tools",
			expected: []string{"jenkins", "jenkins_ci", "jenkins_ci_tools"},
		},
		{
			field:    "-jenkins",
			expected: []string{"jenkins"},
		},
		{
			field:    "jenkins_",
			expected: []string{"jenkins"},
		},
		{
			field:    "",
			expected: nil,
		},
		{
			field:    "-",
			expected: nil,
		},
		{
			field:    "_",
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.field, func(t *testing.T) {
			assert.ElementsMatch(t, test.expected, generateSubSelections(test.field))
		})
	}
}

func Test_addSeparatorVariations(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{
			input:    []string{"jenkins-ci"},
			expected: []string{"jenkins-ci", "jenkins_ci"}, //, "jenkinsci"},
		},
		{
			input:    []string{"jenkins_ci"},
			expected: []string{"jenkins_ci", "jenkins-ci"}, //, "jenkinsci"},
		},
		{
			input:    []string{"jenkins"},
			expected: []string{"jenkins"},
		},
		{
			input:    []string{"jenkins-ci", "circle-ci"},
			expected: []string{"jenkins-ci", "jenkins_ci", "circle-ci", "circle_ci"}, //, "jenkinsci", "circleci"},
		},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.input, ","), func(t *testing.T) {
			val := strset.New(test.input...)
			addSeparatorVariations(val)
			assert.ElementsMatch(t, test.expected, val.List())
		})
	}
}

func Test_productsFromArtifactAndGroupIDs(t *testing.T) {
	tests := []struct {
		groupIDs   []string
		artifactID string
		expected   []string
	}{
		{
			groupIDs:   []string{"org.sonatype.nexus"},
			artifactID: "nexus-extender",
			expected:   []string{"nexus", "nexus-extender"},
		},
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"nexus"},
		},
		{
			groupIDs:   []string{"org.jenkins-ci.plugins"},
			artifactID: "ant",
			expected:   []string{"ant"},
		},
		{
			groupIDs:   []string{"org.jenkins-ci.plugins"},
			artifactID: "antisamy-markup-formatter",
			expected:   []string{"antisamy-markup-formatter"},
		},
		{
			groupIDs:   []string{"io.jenkins.plugins"},
			artifactID: "aws-global-configuration",
			expected:   []string{"aws-global-configuration"},
		},
		{
			groupIDs:   []string{"com.cloudbees.jenkins.plugins"},
			artifactID: "cloudbees-servicenow-jenkins-plugin",
			expected:   []string{"cloudbees-servicenow-jenkins-plugin"},
		},
		{
			groupIDs:   []string{"com.atlassian.confluence.plugins"},
			artifactID: "confluence-mobile-plugin",
			expected:   []string{"confluence-mobile-plugin"},
		},
		{
			groupIDs:   []string{"com.atlassian.confluence.plugins"},
			artifactID: "confluence-view-file-macro",
			expected:   []string{"confluence-view-file-macro"},
		},
		{
			groupIDs:   []string{"com.google.guava"},
			artifactID: "failureaccess",
			expected:   []string{"failureaccess"},
		},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.groupIDs, ",")+":"+test.artifactID, func(t *testing.T) {
			actual := productsFromArtifactAndGroupIDs(test.artifactID, test.groupIDs)
			assert.ElementsMatch(t, test.expected, actual, "different products")
		})
	}
}

func Test_candidateProductsForJava(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []string
	}{
		{
			name: "duplicate groupID in artifactID field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID:    "org.sonatype.nexus",
						ArtifactID: "org.sonatype.nexus",
					},
				},
			},
			expected: []string{"nexus"},
		},
		{
			name: "detect groupID-like value in artifactID field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "org.sonatype.nexus",
					},
				},
			},
			expected: []string{"nexus"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := candidateProductsForJava(test.pkg)
			assert.ElementsMatch(t, test.expected, actual, "different products")
		})
	}
}

func Test_vendorsFromGroupIDs(t *testing.T) {
	tests := []struct {
		groupIDs []string
		expected []string
	}{
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"sonatype", "nexus"},
		},
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"sonatype", "nexus"},
		},
		{
			groupIDs: []string{"org.sonatype.nexus"},
			expected: []string{"sonatype", "nexus"},
		},
		{
			groupIDs: []string{"org.jenkins-ci.plugins"},
			expected: []string{"jenkins-ci", "jenkins"},
		},
		{
			groupIDs: []string{"org.jenkins-ci.plugins"},
			expected: []string{"jenkins-ci", "jenkins"},
		},
		{
			groupIDs: []string{"io.jenkins.plugins"},
			expected: []string{"jenkins"},
		},
		{
			groupIDs: []string{"com.cloudbees.jenkins.plugins"},
			expected: []string{"cloudbees", "jenkins"},
		},
		{
			groupIDs: []string{"com.atlassian.confluence.plugins"},
			expected: []string{"atlassian", "confluence"},
		},
		{
			groupIDs: []string{"com.atlassian.confluence.plugins"},
			expected: []string{"atlassian", "confluence"},
		},
		{
			groupIDs: []string{"com.google.guava"},
			expected: []string{"google", "guava"},
		},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.groupIDs, ","), func(t *testing.T) {
			actual := vendorsFromGroupIDs(test.groupIDs)
			assert.ElementsMatch(t, test.expected, actual, "different vendors")
		})
	}
}

func Test_groupIDsFromJavaPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkg     pkg.Package
		expects []string
	}{
		{
			name: "go case",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						GroupID: "io.jenkins-ci.plugin.thing",
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from artifactID",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "io.jenkins-ci.plugin.thing",
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from main Extension-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							"Extension-Name": "io.jenkins-ci.plugin.thing",
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from named section Extension-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						NamedSections: map[string]map[string]string{
							"section": {
								"Extension-Name": "io.jenkins-ci.plugin.thing",
							},
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from main Automatic-Module-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						Main: map[string]string{
							"Automatic-Module-Name": "io.jenkins-ci.plugin.thing",
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "from named section Automatic-Module-Name field",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					Manifest: &pkg.JavaManifest{
						NamedSections: map[string]map[string]string{
							"section": {
								"Automatic-Module-Name": "io.jenkins-ci.plugin.thing",
							},
						},
					},
				},
			},
			expects: []string{"io.jenkins-ci.plugin.thing"},
		},
		{
			name: "no manifest or pom info",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{},
			},
			expects: nil,
		},
		{
			name:    "no java info",
			pkg:     pkg.Package{},
			expects: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expects, groupIDsFromJavaPackage(test.pkg))
		})
	}
}

func Test_artifactIDFromJavaPackage(t *testing.T) {
	tests := []struct {
		name    string
		pkg     pkg.Package
		expects string
	}{
		{
			name: "go case",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "cloudbees-installation-manager",
					},
				},
			},
			expects: "cloudbees-installation-manager",
		},
		{
			name: "ignore groupID-like things",
			pkg: pkg.Package{
				Metadata: pkg.JavaMetadata{
					PomProperties: &pkg.PomProperties{
						ArtifactID: "io.jenkins-ci.plugin.thing",
					},
				},
			},
			expects: "",
		},
		{
			name:    "no java info",
			pkg:     pkg.Package{},
			expects: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expects, artifactIDFromJavaPackage(test.pkg))
		})
	}
}
