package pkg

import (
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"testing"
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
			name: "jenkins plugin",
			pomProperties: PomProperties{
				Path:       "some path",
				Name:       "some name",
				GroupID:    "com.cloudbees.jenkins.plugins",
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

func TestJavaMetadata_pURL(t *testing.T) {
	tests := []struct {
		metadata JavaMetadata
		expected string
	}{
		{
			metadata: JavaMetadata{
				PomProperties: &PomProperties{
					Path:       "p",
					Name:       "n",
					GroupID:    "g.id",
					ArtifactID: "a",
					Version:    "v",
				},
			},
			expected: "pkg:maven/g.id/a@v",
		},
		{
			metadata: JavaMetadata{},
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			actual := test.metadata.PackageURL()
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
