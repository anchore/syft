package linux

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func TestIdentifyRelease(t *testing.T) {
	tests := []struct {
		fixture string
		release *Release
	}{
		{
			fixture: "test-fixtures/os/alpine",
			release: &Release{
				PrettyName:   "Alpine Linux v3.11",
				Name:         "Alpine Linux",
				ID:           "alpine",
				IDLike:       nil,
				VersionID:    "3.11.6",
				HomeURL:      "https://alpinelinux.org/",
				BugReportURL: "https://bugs.alpinelinux.org/",
			},
		},
		{
			fixture: "test-fixtures/os/amazon",
			release: &Release{
				PrettyName: "Amazon Linux 2",
				Name:       "Amazon Linux",
				ID:         "amzn",
				IDLike: []string{
					"centos",
					"rhel",
					"fedora",
				},
				Version:   "2",
				VersionID: "2",
				HomeURL:   "https://amazonlinux.com/",
				CPEName:   "cpe:2.3:o:amazon:amazon_linux:2",
			},
		},
		{
			fixture: "test-fixtures/os/busybox",
			release: &Release{
				PrettyName: "BusyBox v1.31.1",
				Name:       "busybox",
				ID:         "busybox",
				IDLike:     []string{"busybox"},
				Version:    "1.31.1",
				VersionID:  "1.31.1",
			},
		},
		{
			fixture: "test-fixtures/os/centos",
			release: &Release{
				PrettyName: "CentOS Linux 8 (Core)",
				Name:       "CentOS Linux",
				ID:         "centos",
				IDLike: []string{"rhel",
					"fedora",
				},
				Version:      "8 (Core)",
				VersionID:    "8",
				HomeURL:      "https://www.centos.org/",
				BugReportURL: "https://bugs.centos.org/",
				CPEName:      "cpe:/o:centos:centos:8",
			},
		},
		{
			fixture: "test-fixtures/os/debian",
			release: &Release{
				PrettyName:   "Debian GNU/Linux 8 (jessie)",
				Name:         "Debian GNU/Linux",
				ID:           "debian",
				IDLike:       nil,
				Version:      "8 (jessie)",
				VersionID:    "8",
				HomeURL:      "http://www.debian.org/",
				SupportURL:   "http://www.debian.org/support",
				BugReportURL: "https://bugs.debian.org/",
			},
		},
		{
			fixture: "test-fixtures/os/fedora",
			release: &Release{
				PrettyName:       "Fedora Linux 36 (Container Image)",
				Name:             "Fedora Linux",
				ID:               "fedora",
				IDLike:           nil,
				Version:          "36 (Container Image)",
				VersionID:        "36",
				Variant:          "Container Image",
				VariantID:        "container",
				HomeURL:          "https://fedoraproject.org/",
				SupportURL:       "https://ask.fedoraproject.org/",
				BugReportURL:     "https://bugzilla.redhat.com/",
				PrivacyPolicyURL: "https://fedoraproject.org/wiki/Legal:PrivacyPolicy",
				CPEName:          "cpe:/o:fedoraproject:fedora:36",
				SupportEnd:       "2023-05-16",
			},
		},
		{
			fixture: "test-fixtures/os/redhat",
			release: &Release{
				PrettyName:   "Red Hat Enterprise Linux Server 7.3 (Maipo)",
				Name:         "Red Hat Enterprise Linux Server",
				ID:           "rhel",
				IDLike:       []string{"fedora"},
				Version:      "7.3 (Maipo)",
				VersionID:    "7.3",
				HomeURL:      "https://www.redhat.com/",
				BugReportURL: "https://bugzilla.redhat.com/",
				CPEName:      "cpe:/o:redhat:enterprise_linux:7.3:GA:server",
			},
		},
		{
			fixture: "test-fixtures/os/ubuntu",
			release: &Release{
				PrettyName:       "Ubuntu 20.04 LTS",
				Name:             "Ubuntu",
				ID:               "ubuntu",
				IDLike:           []string{"debian"},
				Version:          "20.04 LTS (Focal Fossa)",
				VersionCodename:  "focal",
				VersionID:        "20.04",
				HomeURL:          "https://www.ubuntu.com/",
				SupportURL:       "https://help.ubuntu.com/",
				BugReportURL:     "https://bugs.launchpad.net/ubuntu/",
				PrivacyPolicyURL: "https://www.ubuntu.com/legal/terms-and-policies/privacy-policy",
			},
		},
		{
			fixture: "test-fixtures/os/oraclelinux",
			release: &Release{
				PrettyName:   "Oracle Linux Server 8.3",
				Name:         "Oracle Linux Server",
				ID:           "ol",
				IDLike:       []string{"fedora"},
				Version:      "8.3",
				VersionID:    "8.3",
				Variant:      "Server",
				VariantID:    "server",
				HomeURL:      "https://linux.oracle.com/",
				BugReportURL: "https://bugzilla.oracle.com/",
				CPEName:      "cpe:/o:oracle:linux:8:3:server",
			},
		},
		{
			fixture: "test-fixtures/os/empty",
		},
		{
			fixture: "test-fixtures/os/custom",
			release: &Release{
				PrettyName: "CentOS Linux 8 (Core)",
				Name:       "Scientific Linux",
				ID:         "scientific",
				IDLike: []string{
					"rhel",
					"fedora",
				},
				Version:      "16 (Core)",
				VersionID:    "8",
				HomeURL:      "https://www.centos.org/",
				BugReportURL: "https://bugs.centos.org/",
				CPEName:      "cpe:/o:centos:centos:8",
			},
		},
		{
			fixture: "test-fixtures/os/opensuse-leap",
			release: &Release{
				PrettyName: "openSUSE Leap 15.2",
				Name:       "openSUSE Leap",
				ID:         "opensuse-leap",
				IDLike: []string{
					"suse",
					"opensuse",
				},
				Version:      "15.2",
				VersionID:    "15.2",
				HomeURL:      "https://www.opensuse.org/",
				BugReportURL: "https://bugs.opensuse.org",
				CPEName:      "cpe:/o:opensuse:leap:15.2",
			},
		},
		{
			fixture: "test-fixtures/os/sles",
			release: &Release{
				PrettyName: "SUSE Linux Enterprise Server 15 SP2",
				Name:       "SLES",
				ID:         "sles",
				IDLike:     []string{"suse"},
				Version:    "15-SP2",
				VersionID:  "15.2",
				CPEName:    "cpe:/o:suse:sles:15:sp2",
			},
		},
		{
			fixture: "test-fixtures/os/photon",
			release: &Release{
				PrettyName:   "VMware Photon OS/Linux",
				Name:         "VMware Photon OS",
				ID:           "photon",
				IDLike:       nil,
				Version:      "2.0",
				VersionID:    "2.0",
				HomeURL:      "https://vmware.github.io/photon/",
				BugReportURL: "https://github.com/vmware/photon/issues",
			},
		},
		{
			fixture: "test-fixtures/os/arch",
			release: &Release{
				PrettyName:   "Arch Linux",
				Name:         "Arch Linux",
				ID:           "arch",
				IDLike:       nil,
				BuildID:      "rolling",
				HomeURL:      "https://www.archlinux.org/",
				SupportURL:   "https://bbs.archlinux.org/",
				BugReportURL: "https://bugs.archlinux.org/",
			},
		},
		{
			fixture: "test-fixtures/partial-fields/missing-id",
			release: &Release{
				Name:      "Debian GNU/Linux",
				IDLike:    []string{"debian"},
				VersionID: "8",
			},
		},
		{
			fixture: "test-fixtures/partial-fields/unknown-id",
			release: &Release{
				Name:      "Debian GNU/Linux",
				ID:        "my-awesome-distro",
				IDLike:    []string{"debian"},
				VersionID: "8",
			},
		},
		{
			fixture: "test-fixtures/partial-fields/missing-version",
			release: &Release{
				Name:   "Debian GNU/Linux",
				IDLike: []string{"debian"},
			},
		},
		{
			fixture: "test-fixtures/os/centos6",
			release: &Release{
				PrettyName: "centos",
				Name:       "centos",
				ID:         "centos",
				IDLike:     []string{"centos"},
				Version:    "6",
				VersionID:  "6",
				CPEName:    "cpe:/o:centos:linux:6:GA",
			},
		},
		{
			fixture: "test-fixtures/os/centos5",
			release: &Release{
				PrettyName: "CentOS",
				Name:       "centos",
				ID:         "centos",
				IDLike:     []string{"centos"},
				Version:    "5.7",
				VersionID:  "5.7",
			},
		},
		{
			fixture: "test-fixtures/os/mariner",
			release: &Release{
				PrettyName:   "CBL-Mariner/Linux",
				Name:         "Common Base Linux Mariner",
				ID:           "mariner",
				IDLike:       nil,
				Version:      "1.0.20210901",
				VersionID:    "1.0",
				HomeURL:      "https://aka.ms/cbl-mariner",
				SupportURL:   "https://aka.ms/cbl-mariner",
				BugReportURL: "https://aka.ms/cbl-mariner",
			},
		},
		{
			fixture: "test-fixtures/os/rockylinux",
			release: &Release{
				PrettyName: "Rocky Linux 8.4 (Green Obsidian)",
				Name:       "Rocky Linux",
				ID:         "rocky",
				IDLike: []string{
					"rhel",
					"fedora",
				},
				Version:      "8.4 (Green Obsidian)",
				VersionID:    "8.4",
				HomeURL:      "https://rockylinux.org/",
				BugReportURL: "https://bugs.rockylinux.org/",
				CPEName:      "cpe:/o:rocky:rocky:8.4:GA",
			},
		},
		{
			fixture: "test-fixtures/os/almalinux",
			release: &Release{
				PrettyName: "AlmaLinux 8.4 (Electric Cheetah)",
				Name:       "AlmaLinux",
				ID:         "almalinux",
				IDLike: []string{
					"rhel",
					"centos",
					"fedora",
				},
				Version:      "8.4 (Electric Cheetah)",
				VersionID:    "8.4",
				HomeURL:      "https://almalinux.org/",
				BugReportURL: "https://bugs.almalinux.org/",
				CPEName:      "cpe:/o:almalinux:almalinux:8.4:GA",
			},
		},
		{
			fixture: "test-fixtures/os/wolfi",
			release: &Release{
				PrettyName: "Wolfi",
				Name:       "Wolfi",
				ID:         "wolfi",
				VersionID:  "20220914",
				HomeURL:    "https://wolfi.dev",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			s, err := directorysource.New(directorysource.Config{
				Path: test.fixture,
			})
			require.NoError(t, err)

			resolver, err := s.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			assert.Equal(t, test.release, IdentifyRelease(resolver))
		})
	}
}

func TestParseOsRelease(t *testing.T) {

	tests := []struct {
		fixture string
		release *Release
	}{
		{
			fixture: "test-fixtures/ubuntu-20.04",

			release: &Release{
				PrettyName:       "Ubuntu 20.04 LTS",
				Name:             "Ubuntu",
				ID:               "ubuntu",
				IDLike:           []string{"debian"},
				Version:          "20.04 LTS (Focal Fossa)",
				VersionID:        "20.04",
				VersionCodename:  "focal",
				HomeURL:          "https://www.ubuntu.com/",
				SupportURL:       "https://help.ubuntu.com/",
				BugReportURL:     "https://bugs.launchpad.net/ubuntu/",
				PrivacyPolicyURL: "https://www.ubuntu.com/legal/terms-and-policies/privacy-policy",
			},
		},

		{
			fixture: "test-fixtures/debian-8",

			release: &Release{
				PrettyName:   "Debian GNU/Linux 8 (jessie)",
				Name:         "Debian GNU/Linux",
				ID:           "debian",
				IDLike:       nil,
				Version:      "8 (jessie)",
				VersionID:    "8",
				HomeURL:      "http://www.debian.org/",
				SupportURL:   "http://www.debian.org/support",
				BugReportURL: "https://bugs.debian.org/",
			},
		},

		{
			fixture: "test-fixtures/centos-8",

			release: &Release{
				PrettyName: "CentOS Linux 8 (Core)",
				Name:       "CentOS Linux",
				ID:         "centos",
				IDLike: []string{
					"rhel",
					"fedora",
				},
				Version:      "8 (Core)",
				VersionID:    "8",
				HomeURL:      "https://www.centos.org/",
				BugReportURL: "https://bugs.centos.org/",
				CPEName:      "cpe:/o:centos:centos:8",
			},
		},

		{
			fixture: "test-fixtures/rhel-8",

			release: &Release{
				PrettyName:   "Red Hat Enterprise Linux 8.1 (Ootpa)",
				Name:         "Red Hat Enterprise Linux",
				ID:           "rhel",
				IDLike:       []string{"fedora"},
				Version:      "8.1 (Ootpa)",
				VersionID:    "8.1",
				HomeURL:      "https://www.redhat.com/",
				BugReportURL: "https://bugzilla.redhat.com/",
				CPEName:      "cpe:/o:redhat:enterprise_linux:8.1:GA",
			},
		},

		{
			fixture: "test-fixtures/unprintable",

			release: &Release{
				PrettyName:   "Debian GNU/Linux 8 (jessie)",
				Name:         "Debian GNU/Linux",
				ID:           "debian",
				IDLike:       nil,
				Version:      "8 (jessie)",
				VersionID:    "8",
				HomeURL:      "http://www.debian.org/",
				SupportURL:   "http://www.debian.org/support",
				BugReportURL: "https://bugs.debian.org/",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture,
			func(t *testing.T) {
				release,
					err := parseOsRelease(retrieveFixtureContentsAsString(test.fixture,
					t))
				require.NoError(t,
					err)
				assert.Equal(t,
					test.release,
					release)
			})
	}

}

func TestParseSystemReleaseCPE(t *testing.T) {
	tests := []struct {
		fixture string
		release *Release
	}{
		{
			fixture: "test-fixtures/os/centos6/etc/system-release-cpe",
			release: &Release{
				PrettyName: "centos",
				Name:       "centos",
				ID:         "centos",
				IDLike:     []string{"centos"},
				Version:    "6",
				VersionID:  "6",
				CPEName:    "cpe:/o:centos:linux:6:GA",
			},
		},
		{
			fixture: "test-fixtures/bad-system-release-cpe",
			release: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			contents := retrieveFixtureContentsAsString(test.fixture, t)
			release, err := parseSystemReleaseCPE(contents)
			require.NoError(t, err)
			if test.release == nil {
				assert.Nil(t, release)
				return
			}

			assert.Equal(t, test.release, release)
		})
	}
}

func TestParseRedhatRelease(t *testing.T) {
	tests := []struct {
		fixture string
		name    string
		release *Release
	}{
		{
			fixture: "test-fixtures/os/centos5/etc/redhat-release",
			name:    "Centos 5",
			release: &Release{
				PrettyName: "CentOS",
				Name:       "centos",
				ID:         "centos",
				IDLike:     []string{"centos"},
				Version:    "5.7",
				VersionID:  "5.7",
			},
		},
		{
			fixture: "test-fixtures/bad-redhat-release",
			name:    "Centos 5 Bad Redhat Release",
			release: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			release, err := parseRedhatRelease(retrieveFixtureContentsAsString(test.fixture, t))
			require.NoError(t, err)
			if test.release == nil {
				assert.Nil(t, release)
				return
			}

			assert.Equal(t, test.release, release)
		})
	}
}

func retrieveFixtureContentsAsString(fixturePath string, t *testing.T) string {
	fixture, err := os.Open(fixturePath)
	if err != nil {
		t.Fatalf("could not open test fixture=%s: %+v", fixturePath, err)
	}
	defer fixture.Close()

	b, err := io.ReadAll(fixture)
	if err != nil {
		t.Fatalf("unable to read fixture file: %+v", err)
	}

	return string(b)
}
