package cataloger

import (
	"fmt"
	"sort"
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
				"cpe:2.3:a:*:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name-part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name-part:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name-part:name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name-part:name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:*:name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name_part:3.2:*:*:*:*:python:*:*",
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
				"cpe:2.3:a:*:python-name-part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:python-name-part:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:*:python_name_part:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:python_name_part:3.2:*:*:*:*:python:*:*",
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
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python-name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python-name:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:python_name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:python_name:name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:*:python-name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:python-name:3.2:*:*:*:*:python:*:*",
				"cpe:2.3:a:*:python_name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:python_name:3.2:*:*:*:*:python:*:*",
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
			name: "jenkins package identified via pkg type",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.JenkinsPluginPkg,
			},
			expected: []string{
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
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
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
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
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
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
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
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
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
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
				"cpe:2.3:a:*:name:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:jenkins:*:*",
				"cpe:2.3:a:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*",
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
				"cpe:2.3:a:*:jira_client_core:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:jira_client_core:3.2:*:*:*:*:java:*:*",
				"cpe:2.3:a:*:jira_client_core:3.2:*:*:*:*:maven:*:*",
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
				"cpe:2.3:a:*:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:*:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:*:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:*:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:jenkins:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:jenkins:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees-installation-manager:jenkins:2.89.0.33:*:*:*:*:maven:*:*",
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
				"cpe:2.3:a:cloudbees_installation_manager:jenkins:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:jenkins:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:cloudbees_installation_manager:jenkins:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jenkins:cloudbees-installation-manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:cloudbees-installation-manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:jenkins:cloudbees-installation-manager:2.89.0.33:*:*:*:*:maven:*:*",
				"cpe:2.3:a:jenkins:cloudbees_installation_manager:2.89.0.33:*:*:*:*:*:*:*",
				"cpe:2.3:a:jenkins:cloudbees_installation_manager:2.89.0.33:*:*:*:*:java:*:*",
				"cpe:2.3:a:jenkins:cloudbees_installation_manager:2.89.0.33:*:*:*:*:maven:*:*",
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
				"cpe:2.3:a:*:something:3.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:*:something:3.2:*:*:*:*:go:*:*",
				"cpe:2.3:a:*:something:3.2:*:*:*:*:golang:*:*",
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

			extra := strset.Difference(actualCpeSet, expectedCpeSet).List()
			sort.Strings(extra)
			for _, d := range extra {
				t.Errorf("extra CPE: %+v", d)
			}

			missing := strset.Difference(expectedCpeSet, actualCpeSet).List()
			sort.Strings(missing)
			for _, d := range missing {
				t.Errorf("missing CPE: %+v", d)
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
			expected: []string{"some-jenkins-plugin", "some_jenkins_plugin"},
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
