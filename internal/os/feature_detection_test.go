package os_test

import (
	"context"
	"io"
	stdos "os"
	"path"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/internal/os"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/internal/task"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
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

func Test_findUbuntuFeatures(t *testing.T) {
	tests := []struct {
		name      string
		dir       string
		releaseID string
		packages  []pkg.Package
		expected  bool
	}{
		{
			name:      "esm apt source present",
			dir:       "testdata/ubuntu_esm_apt",
			releaseID: "ubuntu",
			expected:  true,
		},
		{
			name:      "esm apt source in DEB822 .sources format",
			dir:       "testdata/ubuntu_esm_deb822",
			releaseID: "ubuntu",
			expected:  true,
		},
		{
			name:      "esm evidence in apt auth.conf.d",
			dir:       "testdata/ubuntu_esm_authconf",
			releaseID: "ubuntu",
			expected:  true,
		},
		{
			name:      "active esm service in ubuntu-advantage status",
			dir:       "testdata/ubuntu_esm_status",
			releaseID: "ubuntu",
			expected:  true,
		},
		{
			name:      "only esm-infra enabled (esm-apps disabled)",
			dir:       "testdata/ubuntu_esm_infra_only",
			releaseID: "ubuntu",
			expected:  true,
		},
		{
			name:      "malformed status.json does not panic or match",
			dir:       "testdata/ubuntu_esm_malformed",
			releaseID: "ubuntu",
			expected:  false,
		},
		{
			name:      "installed +esm package version",
			dir:       "testdata/ubuntu_plain",
			releaseID: "ubuntu",
			packages: []pkg.Package{
				{Name: "openssl", Version: "1.1.1f-1ubuntu2.19+esm1", Type: pkg.DebPkg},
			},
			expected: true,
		},
		{
			name:      "installed ~esm package version",
			dir:       "testdata/ubuntu_plain",
			releaseID: "ubuntu",
			packages: []pkg.Package{
				{Name: "libcap2", Version: "1:2.32-1ubuntu0.1~esm1", Type: pkg.DebPkg},
			},
			expected: true,
		},
		{
			name:      "plain ubuntu with no esm evidence",
			dir:       "testdata/ubuntu_plain",
			releaseID: "ubuntu",
			packages: []pkg.Package{
				{Name: "openssl", Version: "1.1.1f-1ubuntu2.19", Type: pkg.DebPkg},
			},
			expected: false,
		},
		{
			name:      "commented esm source and disabled esm service",
			dir:       "testdata/ubuntu_esm_disabled",
			releaseID: "ubuntu",
			expected:  false,
		},
		{
			name:      "esm disabled but +esm package remains installed",
			dir:       "testdata/ubuntu_esm_disabled",
			releaseID: "ubuntu",
			packages: []pkg.Package{
				{Name: "openssl", Version: "1.1.1f-1ubuntu2.19+esm1", Type: pkg.DebPkg},
			},
			expected: true, // durable proof: ESM content is on disk even though the channel is now off
		},
		{
			name:      "fips-only pro host is not plain esm",
			dir:       "testdata/ubuntu_fips_only",
			releaseID: "ubuntu",
			expected:  false, // esm.ubuntu.com/fips must not be folded into the base esm channel
		},
		{
			name:      "non-ubuntu is unaffected by esm evidence",
			dir:       "testdata/ubuntu_esm_apt",
			releaseID: "debian",
			expected:  false,
		},
		{
			name:      "non-ubuntu is unaffected by esm package version",
			dir:       "testdata/ubuntu_plain",
			releaseID: "debian",
			packages: []pkg.Package{
				{Name: "openssl", Version: "1.1.1f-1ubuntu2.19+esm1", Type: pkg.DebPkg},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := fixtureResolverForDir(t, test.dir)

			s := sbom.SBOM{}
			s.Artifacts.LinuxDistribution = &linux.Release{ID: test.releaseID}
			s.Artifacts.Packages = pkg.NewCollection(test.packages...)

			err := os.DetectFeatures(context.Background(), resolver, sbomsync.NewBuilder(&s))
			require.NoError(t, err)

			require.Equal(t, test.expected, s.Artifacts.LinuxDistribution.ExtendedSupport)
		})
	}
}

// a read error in the apt-source signal must not suppress the ubuntu-advantage status signal; the three
// signals are meant to be independent fallbacks.
func Test_findUbuntuFeatures_signalErrorDoesNotSuppressOthers(t *testing.T) {
	resolver := errOnGlobResolver{
		fixtureResolver: fixtureResolverForDir(t, "testdata/ubuntu_esm_status").(fixtureResolver),
		errOnGlob:       "/etc/apt/sources.list.d/*",
	}

	s := sbom.SBOM{}
	s.Artifacts.LinuxDistribution = &linux.Release{ID: "ubuntu"}
	s.Artifacts.Packages = pkg.NewCollection()

	require.NoError(t, os.DetectFeatures(context.Background(), resolver, sbomsync.NewBuilder(&s)))

	// the apt glob errors, but the status.json signal (esm-infra enabled) should still be consulted
	require.True(t, s.Artifacts.LinuxDistribution.ExtendedSupport)
}

// errOnGlobResolver injects a failure for a specific glob to simulate an unreadable apt directory.
type errOnGlobResolver struct {
	fixtureResolver
	errOnGlob string
}

func (r errOnGlobResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	if slices.Contains(patterns, r.errOnGlob) {
		return nil, stdos.ErrPermission
	}
	return r.fixtureResolver.FilesByGlob(patterns...)
}

// fixtureResolver maps in-image logical paths to on-disk fixture files so DetectFeatures can be driven
// without building a container image.
type fixtureResolver struct {
	file.Resolver // unused methods; nil is fine since only the three below are called
	files         map[string]string
}

func (r fixtureResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var out []file.Location
	for logical := range r.files {
		for _, p := range patterns {
			if ok, _ := path.Match(p, logical); ok {
				out = append(out, file.NewLocation(logical))
				break
			}
		}
	}
	return out, nil
}

func (r fixtureResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var out []file.Location
	for _, p := range paths {
		if _, ok := r.files[p]; ok {
			out = append(out, file.NewLocation(p))
		}
	}
	return out, nil
}

func (r fixtureResolver) FileContentsByLocation(l file.Location) (io.ReadCloser, error) {
	return stdos.Open(r.files[l.RealPath])
}

func fixtureResolverForDir(t *testing.T, dir string) file.Resolver {
	t.Helper()
	files := map[string]string{}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d stdos.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		files["/"+filepath.ToSlash(rel)] = p
		return nil
	}))
	return fixtureResolver{files: files}
}
