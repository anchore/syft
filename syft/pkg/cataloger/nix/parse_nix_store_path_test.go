package nix

import (
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_findVersionIsh(t *testing.T) {
	// note: only the package version fields are tested here, the name is tested in parseNixStorePath below.
	tests := []struct {
		name           string
		input          string
		wantIdx        int
		wantVersion    string
		wantPreRelease string
	}{
		{
			name:           "no version",
			input:          "5q7vxm9lc4b9hifc3br4sr8dy7f2h0qa-source",
			wantIdx:        -1,
			wantVersion:    "",
			wantPreRelease: "",
		},
		{
			name:           "semver with overbite into output",
			input:          "/nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin",
			wantIdx:        50,
			wantVersion:    "2.34-210-bin",
			wantPreRelease: "210-bin",
		},
		{
			name:           "multiple versions",
			input:          "5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33",
			wantIdx:        53,
			wantVersion:    "2.33",
			wantPreRelease: "",
		},
		{
			name:           "name ends with number",
			input:          "55nswyz8335lk954y1ccx6as2jbq1z8f-libfido2-1.10.0",
			wantIdx:        42,
			wantVersion:    "1.10.0",
			wantPreRelease: "",
		},
		{
			name:           "major-minor only",
			input:          "q8gnp7r8475p52k9gmdzsrcddw5hirbn-gdbm-1.23",
			wantIdx:        38,
			wantVersion:    "1.23",
			wantPreRelease: "",
		},
		{
			name:           "0-prefixed version field",
			input:          "r705jm2icczpnmfccby3fzfrckfjakx3-perl5.34.1-URI-5.05",
			wantIdx:        48,
			wantVersion:    "5.05",
			wantPreRelease: "",
		},
		{
			name:           "prerelease with alpha prefix",
			input:          "v48s6iddb518j9lc1pk3rcn3x8c2ff0j-bash-interactive-5.1-p16",
			wantIdx:        50,
			wantVersion:    "5.1-p16",
			wantPreRelease: "p16",
		},
		{

			name:           "0-major version",
			input:          "x2f9x5q6qrs6cssx09ylxqyg9q2isi1z-aws-c-http-0.6.15",
			wantIdx:        44,
			wantVersion:    "0.6.15",
			wantPreRelease: "",
		},
		{

			name: "several version fields",
			// note: this package version is fictitious
			input:          "z24qs6f5d1mmwdp73n1jfc3swj4v2c5s-krb5-1.19.3.9.10",
			wantIdx:        38,
			wantVersion:    "1.19.3.9.10",
			wantPreRelease: "",
		},
		{

			name:           "skip drv + major only version",
			input:          "z0fqylhisz47krxv8fd0izm1i2qbswfr-readline63-006.drv",
			wantIdx:        44,
			wantVersion:    "006",
			wantPreRelease: "",
		},
		{

			name:           "prerelease with multiple dashes",
			input:          "zkgyp2vra0bgqm0dv1qi514l5fd0aksx-bash-interactive-5.1-p16-man",
			wantIdx:        50,
			wantVersion:    "5.1-p16-man",
			wantPreRelease: "p16-man",
		},
		{

			name:           "date as major version",
			input:          "0amf0d1dymv9gqcyhhjb9j0l8sn00c56-libedit-20210910-3.1",
			wantIdx:        41,
			wantVersion:    "20210910-3.1",
			wantPreRelease: "3.1",
		},
		{

			name:           "long name",
			input:          "0296qxvn30z9b2ah1g5p97k5wr9k8y78-busybox-static-x86_64-unknown-linux-musl-1.35.0",
			wantIdx:        74,
			wantVersion:    "1.35.0",
			wantPreRelease: "",
		},
		{
			// this accounts for https://nixos.org/manual/nixpkgs/stable/#sec-package-naming
			// > If a package is not a release but a commit from a repository, then the version attribute must
			// > be the date of that (fetched) commit. The date must be in "unstable-YYYY-MM-DD" format.
			// example: https://github.com/NixOS/nixpkgs/blob/798e23beab9b5cba4d6f05e8b243e1d4535770f3/pkgs/servers/webdav-server-rs/default.nix#L14
			name:           "unstable version",
			input:          "q5dhwzcn82by5ndc7g0q83wsnn13qkqw-webdav-server-rs-unstable-2021-08-16",
			wantIdx:        50,
			wantVersion:    "unstable-2021-08-16",
			wantPreRelease: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIdx, gotVersion, gotPreRelease := findVersionIsh(tt.input)
			assert.Equal(t, tt.wantIdx, gotIdx)
			assert.Equal(t, tt.wantVersion, gotVersion)
			assert.Equal(t, tt.wantPreRelease, gotPreRelease)
		})
	}
}

func Test_parseNixStorePath(t *testing.T) {

	tests := []struct {
		source string
		want   *nixStorePath
	}{
		{
			source: "/nix/store/h0cnbmfcn93xm5dg2x27ixhag1cwndga-glibc-2.34-210-bin",
			want: &nixStorePath{
				outputHash: "h0cnbmfcn93xm5dg2x27ixhag1cwndga",
				name:       "glibc",
				version:    "2.34-210",
				output:     "bin",
			},
		},
		{
			source: "/nix/store/0296qxvn30z9b2ah1g5p97k5wr9k8y78-busybox-static-x86_64-unknown-linux-musl-1.35.0",
			want: &nixStorePath{
				outputHash: "0296qxvn30z9b2ah1g5p97k5wr9k8y78",
				name:       "busybox-static-x86_64-unknown-linux-musl",
				version:    "1.35.0",
			},
		},
		{
			source: "/nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33",
			want: &nixStorePath{
				outputHash: "5zzrvdmlkc5rh3k5862krd3wfb3pqhyf",
				name:       "perl5.34.1-TimeDate",
				version:    "2.33",
			},
		},
		{
			source: "/nix/store/q38q8ng57zwjg1h15ry5zx0lb0xyax4b-libcap-2.63-lib",
			want: &nixStorePath{
				outputHash: "q38q8ng57zwjg1h15ry5zx0lb0xyax4b",
				name:       "libcap",
				version:    "2.63",
				output:     "lib",
			},
		},
		{
			source: "/nix/store/p0y8fbpbqr2jm5zfrdll0rgyg2lvp5g2-util-linux-minimal-2.37.4-bin",
			want: &nixStorePath{
				outputHash: "p0y8fbpbqr2jm5zfrdll0rgyg2lvp5g2",
				name:       "util-linux-minimal",
				version:    "2.37.4",
				output:     "bin",
			},
		},
		{
			source: "/nix/store/z24qs6f5d1mmwdp73n1jfc3swj4v2c5s-krb5-1.19.3.9.10",
			want: &nixStorePath{
				outputHash: "z24qs6f5d1mmwdp73n1jfc3swj4v2c5s",
				name:       "krb5",
				version:    "1.19.3.9.10",
			},
		},
		{
			source: "/nix/store/zkgyp2vra0bgqm0dv1qi514l5fd0aksx-bash-interactive-5.1-p16-man",
			want: &nixStorePath{
				outputHash: "zkgyp2vra0bgqm0dv1qi514l5fd0aksx",
				name:       "bash-interactive",
				version:    "5.1-p16",
				output:     "man",
			},
		},
		{
			source: "/nix/store/nwf2y0nc48ybim56308cr5ccvwkabcqc-openssl-1.1.1q",
			want: &nixStorePath{
				outputHash: "nwf2y0nc48ybim56308cr5ccvwkabcqc",
				name:       "openssl",
				version:    "1.1.1q",
			},
		},
		{
			source: "/nix/store/nwv742f1bxv6g78hy9yc6slxdbxlmqhb-kmod-29",
			want: &nixStorePath{
				outputHash: "nwv742f1bxv6g78hy9yc6slxdbxlmqhb",
				name:       "kmod",
				version:    "29",
			},
		},
		{
			source: "/nix/store/n83qx7m848kg51lcjchwbkmlgdaxfckf-tzdata-2022a",
			want: &nixStorePath{
				outputHash: "n83qx7m848kg51lcjchwbkmlgdaxfckf",
				name:       "tzdata",
				version:    "2022a",
			},
		},
		{
			source: "'/nix/store/q5dhwzcn82by5ndc7g0q83wsnn13qkqw-webdav-server-rs-unstable-2021-08-16",
			want: &nixStorePath{
				outputHash: "q5dhwzcn82by5ndc7g0q83wsnn13qkqw",
				name:       "webdav-server-rs",
				version:    "unstable-2021-08-16",
			},
		},
		// negative cases...
		{
			source: "'z33yk02rsr6b4rb56lgb80bnvxx6yw39-?id=21ee35dde73aec5eba35290587d479218c6dd824.drv'",
		},
		{
			source: "/nix/store/yzahni8aig6mdrvcsccgwm2515lcpi5q-git-minimal-2.36.0.drv",
		},
		{
			source: "/nix/store/z9yvxs0s3xdkp5jgmzis4g50bfq3dgvm-0018-pkg-config-derive-prefix-from-prefix.patch",
		},
		{
			source: "/nix/store/w3hl7zrmc9qvzadc0k7cp9ysxiyz88j6-base-system",
		},
		{
			source: "/nix/store/zz1lc28x25fcx6al6xwk3dk8kp7wx47y-Test-RequiresInternet-0.05.tar.gz.drv",
		},
	}
	for _, tt := range tests {
		t.Run(path.Base(tt.source), func(t *testing.T) {
			assert.Equal(t, tt.want, parseNixStorePath(tt.source))
		})
	}
}

func Test_parentNixStorePath(t *testing.T) {

	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "exact path from absolute root",
			source: "/nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33",
			want:   "",
		},
		{
			name:   "exact path from relative root",
			source: "nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33",
			want:   "",
		},
		{
			name:   "clean paths",
			source: "//nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33///",
			want:   "",
		},
		{
			name:   "relative root with subdir file",
			source: "nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33/bin/perl-timedate",
			want:   "nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33",
		},
		{
			name:   "absolute root with with subdir file",
			source: "/nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33/bin/perl-timedate",
			want:   "/nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33",
		},
		{
			name:   "nexted root with with subdir file",
			source: "/somewhere/nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33/bin/perl-timedate",
			want:   "/somewhere/nix/store/5zzrvdmlkc5rh3k5862krd3wfb3pqhyf-perl5.34.1-TimeDate-2.33",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, findParentNixStorePath(tt.source))
		})
	}
}
