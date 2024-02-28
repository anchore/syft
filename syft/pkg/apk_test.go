package pkg

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApkMetadata_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ApkDBEntry
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:  "empty",
			input: "{}",
			want:  ApkDBEntry{},
		},
		{
			name: "string array dependencies",
			input: `{
"package": "scanelf",
"originPackage": "pax-utils",
"maintainer": "Natanael Copa <ncopa@alpinelinux.org>",
"version": "1.3.4-r0",
"license": "GPL-2.0-only",
"architecture": "x86_64",
"url": "https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities",
"description": "Scan ELF binaries for stuff",
"size": 36745,
"installedSize": 94208,
"pullChecksum": "Q1Gcqe+ND8DFOlhM3R0o5KyZjR2oE=",
"gitCommitOfApkPort": "d7ae612a3cc5f827289d915783b4cbf8c7207947",
"files": [
 {
  "path": "/usr"
 }
],
"pullDependencies": ["foo", "bar"]
}`,
			want: ApkDBEntry{
				Package:       "scanelf",
				OriginPackage: "pax-utils",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "1.3.4-r0",
				Architecture:  "x86_64",
				URL:           "https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities",
				Description:   "Scan ELF binaries for stuff",
				Size:          36745,
				InstalledSize: 94208,
				Dependencies:  []string{"foo", "bar"},
				Checksum:      "Q1Gcqe+ND8DFOlhM3R0o5KyZjR2oE=",
				GitCommit:     "d7ae612a3cc5f827289d915783b4cbf8c7207947",
				Files:         []ApkFileRecord{{Path: "/usr"}},
			},
		},
		{
			name: "single string dependencies",
			input: `{
"package": "scanelf",
"originPackage": "pax-utils",
"maintainer": "Natanael Copa <ncopa@alpinelinux.org>",
"version": "1.3.4-r0",
"license": "GPL-2.0-only",
"architecture": "x86_64",
"url": "https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities",
"description": "Scan ELF binaries for stuff",
"size": 36745,
"installedSize": 94208,
"pullChecksum": "Q1Gcqe+ND8DFOlhM3R0o5KyZjR2oE=",
"gitCommitOfApkPort": "d7ae612a3cc5f827289d915783b4cbf8c7207947",
"files": [
 {
  "path": "/usr"
 }
],
"pullDependencies": "foo bar"
}`,
			want: ApkDBEntry{
				Package:       "scanelf",
				OriginPackage: "pax-utils",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "1.3.4-r0",
				Architecture:  "x86_64",
				URL:           "https://wiki.gentoo.org/wiki/Hardened/PaX_Utilities",
				Description:   "Scan ELF binaries for stuff",
				Size:          36745,
				InstalledSize: 94208,
				Dependencies:  []string{"foo", "bar"},
				Checksum:      "Q1Gcqe+ND8DFOlhM3R0o5KyZjR2oE=",
				GitCommit:     "d7ae612a3cc5f827289d915783b4cbf8c7207947",
				Files:         []ApkFileRecord{{Path: "/usr"}},
			},
		},
		{
			name: "null pullDependencies",
			input: `{
"pullDependencies": null
}`,
			want: ApkDBEntry{
				Dependencies: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			var got ApkDBEntry
			err := json.Unmarshal([]byte(tt.input), &got)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSpaceDelimitedStringSlice_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    []string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "empty string",
			data: `""`,
			want: nil,
		},
		{
			name: "single string with one elements",
			data: `"foo"`,
			want: []string{"foo"},
		},
		{
			name: "single string with multiple elements",
			data: `"foo bar"`,
			want: []string{"foo", "bar"},
		},
		{
			name: "string array",
			data: `["foo", "bar"]`,
			want: []string{"foo", "bar"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			element := spaceDelimitedStringSlice{}
			tt.wantErr(t, element.UnmarshalJSON([]byte(tt.data)))
			assert.Equal(t, tt.want, []string(element))
		})
	}
}
