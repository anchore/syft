package dpkg

import (
	"os"
	"testing"

	"github.com/go-test/deep"
)

func compareEntries(t *testing.T, left, right DpkgEntry) {
	t.Helper()
	if diff := deep.Equal(left, right); diff != nil {
		t.Error(diff)
	}
}

func TestSinglePackage(t *testing.T) {
	tests := []struct {
		name     string
		expected DpkgEntry
	}{
		{
			name: "Test Single Package",
			expected: DpkgEntry{
				Package:        "apt",
				Status:         "install ok installed",
				Priority:       "required",
				InstalledSize:  "4064",
				Maintainer:     "APT Development Team <deity@lists.debian.org>",
				Architecture:   "amd64",
				Version:        "1.8.2",
				ReplacesPkgs:   "apt-transport-https (<< 1.5~alpha4~), apt-utils (<< 1.3~exp2~)",
				ProvidesPkgs:   "apt-transport-https (= 1.8.2)",
				DependsPkgs:    "adduser, gpgv | gpgv2 | gpgv1, debian-archive-keyring, libapt-pkg5.0 (>= 1.7.0~alpha3~), libc6 (>= 2.15), libgcc1 (>= 1:3.0), libgnutls30 (>= 3.6.6), libseccomp2 (>= 1.0.1), libstdc++6 (>= 5.2)",
				RecommendsPkgs: "ca-certificates",
				SuggestsPkgs:   "apt-doc, aptitude | synaptic | wajig, dpkg-dev (>= 1.17.2), gnupg | gnupg2 | gnupg1, powermgmt-base",
				ConfigFiles: `
 /etc/apt/apt.conf.d/01autoremove 76120d358bc9037bb6358e737b3050b5
 /etc/cron.daily/apt-compat 49e9b2cfa17849700d4db735d04244f3
 /etc/kernel/postinst.d/apt-auto-removal 4ad976a68f045517cf4696cec7b8aa3a
 /etc/logrotate.d/apt 179f2ed4f85cbaca12fa3d69c2a4a1c3`,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/single")
			if err != nil {
				t.Fatal("Unable to read test_fixtures/single: ", err)
			}

			entry, err := Read(file)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			compareEntries(t, entry, test.expected)

		})
	}
}

func TestMultiplePackage(t *testing.T) {
	tests := []struct {
		name     string
		expected []DpkgEntry
	}{
		{
			name: "Test Multiple Package",
			expected: []DpkgEntry{
				{
					Package:       "tzdata",
					Status:        "install ok installed",
					Priority:      "required",
					InstalledSize: "3036",
					Maintainer:    "GNU Libc Maintainers <debian-glibc@lists.debian.org>",
					Architecture:  "all",
					Version:       "2020a-0+deb10u1",
					ReplacesPkgs:  "libc0.1, libc0.3, libc6, libc6.1",
					ProvidesPkgs:  "tzdata-buster",
					DependsPkgs:   "debconf (>= 0.5) | debconf-2.0",
				},
				{
					Package:       "util-linux",
					Status:        "install ok installed",
					Priority:      "required",
					InstalledSize: "4327",
					Maintainer:    "LaMont Jones <lamont@debian.org>",
					Architecture:  "amd64",
					Version:       "2.33.1-0.1",
					ReplacesPkgs:  "bash-completion (<< 1:2.8), initscripts (<< 2.88dsf-59.2~), login (<< 1:4.5-1.1~), mount (<< 2.29.2-3~), s390-tools (<< 2.2.0-1~), setpriv (<< 2.32.1-0.2~), sysvinit-utils (<< 2.88dsf-59.1~)",
					DependsPkgs:   "fdisk, login (>= 1:4.5-1.1~)",
					SuggestsPkgs:  "dosfstools, kbd | console-tools, util-linux-locales",
					ConfigFiles: `
 /etc/default/hwclock 3916544450533eca69131f894db0ca12
 /etc/init.d/hwclock.sh 1ca5c0743fa797ffa364db95bb8d8d8e
 /etc/pam.d/runuser b8b44b045259525e0fae9e38fdb2aeeb
 /etc/pam.d/runuser-l 2106ea05877e8913f34b2c77fa02be45
 /etc/pam.d/su ce6dcfda3b190a27a455bb38a45ff34a
 /etc/pam.d/su-l 756fef5687fecc0d986e5951427b0c4f`,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := os.Open("test-fixtures/multiple")
			if err != nil {
				t.Fatal("Unable to read: ", err)
			}
			defer file.Close()

			entries, err := ReadAllDpkgEntries(file)
			if err != nil {
				t.Fatal("Unable to read file contents: ", err)
			}

			if len(entries) != 2 {
				t.Fatalf("unexpected number of entries: %d", len(entries))
			}

			for idx, entry := range entries {
				compareEntries(t, entry, test.expected[idx])
			}

		})
	}
}
