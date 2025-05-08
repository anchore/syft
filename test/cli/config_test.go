package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func Test_configLoading(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	defer func() { require.NoError(t, os.Chdir(cwd)) }()

	configsDir := filepath.Join(cwd, "test-fixtures", "configs")
	path := func(path string) string {
		return filepath.Join(configsDir, filepath.Join(strings.Split(path, "/")...))
	}

	type creds struct {
		Authority string `yaml:"authority"`
	}

	type registry struct {
		Credentials []creds `yaml:"auth"`
	}

	type config struct {
		Registry registry `yaml:"registry"`
	}

	tests := []struct {
		name     string
		home     string
		cwd      string
		args     []string
		expected []creds
		err      string
	}{
		{
			name: "single explicit config",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.syft.yaml"),
			},
			expected: []creds{
				{
					Authority: "dir1-authority",
				},
			},
		},
		{
			name: "multiple explicit config",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.syft.yaml"),
				"-c",
				path("dir2/.syft.yaml"),
			},
			expected: []creds{
				{
					Authority: "dir1-authority",
				},
				{
					Authority: "dir2-authority",
				},
			},
		},
		{
			name: "empty profile override",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.syft.yaml"),
				"-c",
				path("dir2/.syft.yaml"),
				"--profile",
				"no-auth",
			},
			expected: []creds{},
		},
		{
			name: "no profiles defined",
			home: configsDir,
			cwd:  configsDir,
			args: []string{
				"--profile",
				"invalid",
			},
			err: "not found in any configuration files",
		},
		{
			name: "invalid profile name",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.syft.yaml"),
				"-c",
				path("dir2/.syft.yaml"),
				"--profile",
				"alt",
			},
			err: "profile not found",
		},
		{
			name: "explicit with profile override",
			home: configsDir,
			cwd:  cwd,
			args: []string{
				"-c",
				path("dir1/.syft.yaml"),
				"-c",
				path("dir2/.syft.yaml"),
				"--profile",
				"alt-auth",
			},
			expected: []creds{
				{
					Authority: "dir1-alt-authority", // dir1 is still first
				},
				{
					Authority: "dir2-alt-authority",
				},
			},
		},
		{
			name: "single in cwd",
			home: configsDir,
			cwd:  path("dir2"),
			args: []string{},
			expected: []creds{
				{
					Authority: "dir2-authority",
				},
			},
		},
		{
			name: "single in home",
			home: path("dir2"),
			cwd:  configsDir,
			args: []string{},
			expected: []creds{
				{
					Authority: "dir2-authority",
				},
			},
		},
		{
			name: "inherited in cwd",
			home: path("dir1"),
			cwd:  path("dir2"),
			args: []string{},
			expected: []creds{
				{
					Authority: "dir2-authority", // dir2 is in cwd, giving higher priority
				},
				{
					Authority: "dir1-authority", // home has "lower priority and should be after"
				},
			},
		},
		{
			name: "inherited profile override",
			home: path("dir1"),
			cwd:  path("dir2"),
			args: []string{
				"--profile",
				"alt-auth",
			},
			expected: []creds{
				{
					Authority: "dir2-alt-authority", // dir2 is in cwd, giving higher priority
				},
				{
					Authority: "dir1-alt-authority", // dir1 is home, lower priority
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, os.Chdir(test.cwd))
			defer func() { require.NoError(t, os.Chdir(cwd)) }()
			env := map[string]string{
				"HOME":            test.home,
				"XDG_CONFIG_HOME": test.home,
			}
			_, stdout, stderr := runSyft(t, env, append([]string{"config", "--load"}, test.args...)...)
			if test.err != "" {
				require.Contains(t, stderr, test.err)
				return
			} else {
				require.Empty(t, stderr)
			}
			got := config{}
			err = yaml.NewDecoder(strings.NewReader(stdout)).Decode(&got)
			require.NoError(t, err)
			require.Equal(t, test.expected, got.Registry.Credentials)
		})
	}
}
