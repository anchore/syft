package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
)

func Test_defaultMavenLocalRepoDir(t *testing.T) {
	home, err := homedir.Dir()
	require.NoError(t, err)

	fixtures, err := filepath.Abs("test-fixtures")
	require.NoError(t, err)

	tests := []struct {
		name     string
		home     string
		expected string
	}{
		{
			name:     "default",
			expected: filepath.Join(home, ".m2", "repository"),
			home:     "",
		},
		{
			name:     "alternate dir",
			expected: "/some/other/repo",
			home:     "test-fixtures/local-repository-settings",
		},
		{
			name:     "explicit home",
			expected: filepath.Join(fixtures, ".m2", "repository"),
			home:     "test-fixtures",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			homedir.Reset()
			defer homedir.Reset()
			if test.home != "" {
				home, err := filepath.Abs(test.home)
				require.NoError(t, err)
				t.Setenv("HOME", home)
			}
			got := defaultMavenLocalRepoDir()
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_getSettingsXmlLocalRepository(t *testing.T) {
	tests := []struct {
		file     string
		expected string
	}{
		{
			expected: "/some/other/repo",
			file:     "test-fixtures/local-repository-settings/.m2/settings.xml",
		},
		{
			expected: "",
			file:     "invalid",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			f, _ := os.Open(test.file)
			defer internal.CloseAndLogError(f, test.file)
			got := getSettingsXMLLocalRepository(f)
			require.Equal(t, test.expected, got)
		})
	}
}

func Test_remotePomURL(t *testing.T) {
	tests := []struct {
		name       string
		groupID    string
		artifactID string
		version    string
		expected   string
	}{
		{
			name:       "remotePomURL correctly assembles the pom URL",
			groupID:    "org.springframework.boot",
			artifactID: "spring-boot-starter-test",
			version:    "3.1.5",
			expected:   "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-starter-test/3.1.5/spring-boot-starter-test-3.1.5.pom",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requestURL, err := remotePomURL(mavenBaseURL, tc.groupID, tc.artifactID, tc.version)
			require.NoError(t, err, "expected no err; got %w", err)
			require.Equal(t, tc.expected, requestURL)
		})
	}
}
