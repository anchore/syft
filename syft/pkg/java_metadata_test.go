package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPomProperties_PkgTypeIndicated(t *testing.T) {
	cases := []struct {
		name          string
		pomProperties PomProperties
		expectedType  Type
	}{
		{
			name: "regular Java package",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "some group ID",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JavaPkg,
		},
		{
			name: "cloudbees jenkins plugin",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "com.cloudbees.jenkins.plugins",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JenkinsPluginPkg,
		},
		{
			name: "jenkins.io plugin",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "io.jenkins.plugins",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JenkinsPluginPkg,
		},
		{
			name: "jenkins-ci.io plugin",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "io.jenkins-ci.plugins",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JenkinsPluginPkg,
		},
		{
			name: "jenkins-ci.org plugin",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "org.jenkins-ci.plugins",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JenkinsPluginPkg,
		},
		{
			name: "jenkins.org plugin",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "org.jenkins.plugins",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JenkinsPluginPkg,
		},
		{
			name: "jenkins plugin prefix",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "com.cloudbees.jenkins.plugins.bluesteel",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JenkinsPluginPkg,
		},
		{
			name: "jenkins.plugin somewhere in group id",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "org.wagoodman.jenkins.plugins.something",
				ArtifactID: "some artifact ID",
				Version:    "1",
			},
			expectedType: JenkinsPluginPkg,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.pomProperties.PkgTypeIndicated()
			assert.Equal(t, tc.expectedType, actual)
		})
	}
}
