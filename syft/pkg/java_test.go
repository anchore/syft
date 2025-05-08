package pkg

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestPomProperties_PkgTypeIndicated(t *testing.T) {
	cases := []struct {
		name          string
		pomProperties JavaPomProperties
		expectedType  Type
	}{
		{
			name: "regular Java package",
			pomProperties: JavaPomProperties{
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
			pomProperties: JavaPomProperties{
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
			pomProperties: JavaPomProperties{
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
			pomProperties: JavaPomProperties{
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
			pomProperties: JavaPomProperties{
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
			pomProperties: JavaPomProperties{
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
			pomProperties: JavaPomProperties{
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
			pomProperties: JavaPomProperties{
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

func Test_legacyJavaManifest_toNewManifest(t *testing.T) {
	tests := []struct {
		name string
		lm   legacyJavaManifest
		want JavaManifest
	}{
		{
			name: "empty",
			lm:   legacyJavaManifest{},
			want: JavaManifest{},
		},
		{
			name: "main sections are sorted",
			lm: legacyJavaManifest{
				Main: map[string]string{
					"a key": "a value",
					"b key": "b value",
					"c key": "c value",
				},
			},
			want: JavaManifest{Main: KeyValues{
				{
					Key:   "a key",
					Value: "a value",
				},
				{
					Key:   "b key",
					Value: "b value",
				},
				{
					Key:   "c key",
					Value: "c value",
				},
			}},
		},
		{
			name: "named sections have their name in the result",
			lm: legacyJavaManifest{
				NamedSections: map[string]map[string]string{
					"a section": {
						"a key": "a value",
						"b key": "b value",
						"c key": "c value",
					},
					"b section": {
						"d key": "d value",
						"e key": "e value",
						"f key": "f value",
					},
				},
			},
			want: JavaManifest{Sections: []KeyValues{
				{
					{
						Key:   "Name",
						Value: "a section",
					},
					{
						Key:   "a key",
						Value: "a value",
					},
					{
						Key:   "b key",
						Value: "b value",
					},
					{
						Key:   "c key",
						Value: "c value",
					},
				},
				{
					{
						Key:   "Name",
						Value: "b section",
					},
					{
						Key:   "d key",
						Value: "d value",
					},
					{
						Key:   "e key",
						Value: "e value",
					},
					{
						Key:   "f key",
						Value: "f value",
					},
				},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.lm.toNewManifest()); diff != "" {
				t.Errorf("unexpected diff in manifest (-want +got):\n%s", diff)
			}
		})
	}
}
