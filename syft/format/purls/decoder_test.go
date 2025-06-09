package purls

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/cmptest"
	"github.com/anchore/syft/syft/pkg"
)

func TestDecoder_Decode(t *testing.T) {
	tests := []struct {
		purl     string
		expected []pkg.Package
	}{
		{
			purl: "pkg:generic/some-package@1.2.3",
			expected: []pkg.Package{
				{
					Name:    "some-package",
					Type:    pkg.UnknownPkg,
					Version: "1.2.3",
					PURL:    "pkg:generic/some-package@1.2.3",
				},
			},
		},
		{
			purl: "pkg:npm/some-package@1.2.3",
			expected: []pkg.Package{
				{
					Name:     "some-package",
					Type:     pkg.NpmPkg,
					Language: pkg.JavaScript,
					Version:  "1.2.3",
					PURL:     "pkg:npm/some-package@1.2.3",
				},
			},
		},
		{
			purl: "pkg:apk/curl@7.61.1",
			expected: []pkg.Package{
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1",
				},
			},
		},
		{
			purl: "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
			expected: []pkg.Package{
				{
					Name:    "sysv-rc",
					Version: "2.88dsf-59",
					Type:    pkg.DebPkg,
					PURL:    "pkg:deb/debian/sysv-rc@2.88dsf-59?arch=all&distro=debian-jessie&upstream=sysvinit",
				},
			},
		},
		{
			purl: "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
			expected: []pkg.Package{
				{
					Name:    "libcrypto3",
					Version: "3.3.2",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/libcrypto3@3.3.2?upstream=openssl",
				},
			},
		},
		{
			purl: "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1", // %40 is @
			expected: []pkg.Package{
				{
					Name:    "libcrypto3",
					Version: "3.3.2",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/libcrypto3@3.3.2?upstream=openssl%403.2.1",
				},
			},
		},
		{
			purl: "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
			expected: []pkg.Package{
				{
					Name:    "systemd-x",
					Version: "239-82.el8_10.2",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/systemd-x@239-82.el8_10.2?arch=aarch64&distro=rhel-8.10&upstream=systemd-239-82.el8_10.2.src.rpm",
				},
			},
		},
		{
			purl: "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
			expected: []pkg.Package{
				{
					Name:    "dbus-common",
					Version: "1:1.12.8-26.el8",
					Type:    pkg.RpmPkg,
					PURL:    "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
				},
			},
		},
		{
			purl: "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
			expected: []pkg.Package{
				{
					Name:    "curl",
					Version: "7.61.1",
					Type:    pkg.ApkPkg,
					PURL:    "pkg:apk/curl@7.61.1?arch=aarch64&distro=alpine-3.20.3",
				},
			},
		},
		{
			purl: "pkg:golang/k8s.io/ingress-nginx@v1.11.2",
			expected: []pkg.Package{
				{
					Name:     "k8s.io/ingress-nginx",
					Version:  "v1.11.2",
					Type:     pkg.GoModulePkg,
					Language: pkg.Go,
					PURL:     "pkg:golang/k8s.io/ingress-nginx@v1.11.2",
				},
			},
		},
		{
			purl: "pkg:golang/github.com/wazuh/wazuh@v4.5.0",
			expected: []pkg.Package{
				{
					Name:     "github.com/wazuh/wazuh",
					Version:  "v4.5.0",
					Type:     pkg.GoModulePkg,
					PURL:     "pkg:golang/github.com/wazuh/wazuh@v4.5.0",
					Language: pkg.Go,
				},
			},
		},
		{
			purl: "pkg:golang/wazuh@v4.5.0",
			expected: []pkg.Package{
				{
					Name:     "wazuh",
					Version:  "v4.5.0",
					Type:     pkg.GoModulePkg,
					PURL:     "pkg:golang/wazuh@v4.5.0",
					Language: pkg.Go,
				},
			},
		},
		{
			purl: "pkg:maven/org.apache/some-pkg@4.11.3",
			expected: []pkg.Package{
				{
					Name:     "some-pkg",
					Version:  "4.11.3",
					Type:     pkg.JavaPkg,
					PURL:     "pkg:maven/org.apache/some-pkg@4.11.3",
					Language: pkg.Java,
					// we intentionally do not claim we found a pom properties file (don't derive this from the purl).
					// but we need a metadata allocated since all Java packages have a this metadata type (a consistency point)
					Metadata: pkg.JavaArchive{},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.purl, func(t *testing.T) {
			dec := NewFormatDecoder()
			got, _, _, err := dec.Decode(strings.NewReader(test.purl))
			require.NoError(t, err)

			if diff := cmp.Diff(test.expected, got.Artifacts.Packages.Sorted(), cmptest.DefaultOptions()...); diff != "" {
				t.Errorf("expected packages (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_DecodeEncodeCycle(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "basic",
			input: "pkg:generic/some-package@1.2.3",
		},
		{
			name:  "multiple",
			input: "pkg:generic/pkg1\npkg:generic/pkg2\n\npkg:npm/@vercel/ncc@2.9.5",
		},
		{
			name:  "java",
			input: "pkg:maven/org.apache/some-thing@4.11.3",
		},
		{
			name:  "leading whitespace",
			input: "     \n \t  pkg:maven/org.apache/some-thing@4.11.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := NewFormatDecoder()
			decodedSBOM, _, _, err := dec.Decode(strings.NewReader(tt.input))
			require.NoError(t, err)

			var buf bytes.Buffer
			enc := NewFormatEncoder()
			require.NoError(t, enc.Encode(&buf, *decodedSBOM))

			in := strings.TrimSpace(regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(tt.input), "\n"))
			expected := strings.Split(in, "\n")
			slices.Sort(expected)

			got := strings.Split(strings.TrimSpace(buf.String()), "\n")
			slices.Sort(got)
			require.EqualValues(t, expected, got)

			for _, item := range got {
				// require every result is a valid PURL -- no whitespace lines, etc.
				_, err = packageurl.FromString(item)
				require.NoError(t, err)
			}
		})
	}
}
