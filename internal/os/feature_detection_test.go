package os_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/internal/os"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_EnvironmentTask(t *testing.T) {
	tests := []struct {
		name     string
		expected linux.Release
	}{
		{
			name: "not_rhel",
			expected: linux.Release{
				PrettyName: "Red Hat Enterprise Linux 9.4 (Plow)",
				Name:       "Red Hat Enterprise Linux",
				ID:         "not-rhel",
				IDLike: []string{
					"fedora",
				},
				Version:         "9.4 (Plow)",
				VersionID:       "9.4",
				HomeURL:         "https://www.redhat.com/",
				BugReportURL:    "https://issues.redhat.com/",
				CPEName:         "cpe:/o:redhat:enterprise_linux:9::baseos",
				ExtendedSupport: false, // important
			},
		},
		{
			name: "rhel_content_manifests",
			expected: linux.Release{
				PrettyName: "Red Hat Enterprise Linux 9.4 (Plow)",
				Name:       "Red Hat Enterprise Linux",
				ID:         "rhel",
				IDLike: []string{
					"fedora",
				},
				Version:         "9.4 (Plow)",
				VersionID:       "9.4",
				HomeURL:         "https://www.redhat.com/",
				BugReportURL:    "https://issues.redhat.com/",
				CPEName:         "cpe:/o:redhat:enterprise_linux:9::baseos",
				ExtendedSupport: true, // important
			},
		},
		{
			name: "rhel_no_manifests",
			expected: linux.Release{
				PrettyName: "Red Hat Enterprise Linux 9.4 (Plow)",
				Name:       "Red Hat Enterprise Linux",
				ID:         "rhel",
				IDLike: []string{
					"fedora",
				},
				Version:         "9.4 (Plow)",
				VersionID:       "9.4",
				HomeURL:         "https://www.redhat.com/",
				BugReportURL:    "https://issues.redhat.com/",
				CPEName:         "cpe:/o:redhat:enterprise_linux:9::baseos",
				ExtendedSupport: false, // important
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tarPath := imagetest.GetFixtureImageTarPath(t, test.name)

			// get the source
			theSource, err := syft.GetSource(context.Background(), tarPath, syft.DefaultGetSourceConfig().WithSources("docker-archive"))
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, theSource.Close())
			})

			resolver, err := theSource.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			s := sbom.SBOM{}
			err = task.NewEnvironmentTask().Execute(context.Background(), resolver, sbomsync.NewBuilder(&s))
			require.NoError(t, err)

			err = os.DetectFeatures(context.Background(), resolver, sbomsync.NewBuilder(&s))
			require.NoError(t, err)

			require.Equal(t, &test.expected, s.Artifacts.LinuxDistribution)
		})
	}
}
