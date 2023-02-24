package pkg

import (
	"encoding/json"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApkMetadata_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ApkMetadata
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:  "empty",
			input: "{}",
			want:  ApkMetadata{},
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
			want: ApkMetadata{
				Package:       "scanelf",
				OriginPackage: "pax-utils",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "1.3.4-r0",
				License:       "GPL-2.0-only",
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
			want: ApkMetadata{
				Package:       "scanelf",
				OriginPackage: "pax-utils",
				Maintainer:    "Natanael Copa <ncopa@alpinelinux.org>",
				Version:       "1.3.4-r0",
				License:       "GPL-2.0-only",
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
			want: ApkMetadata{
				Dependencies: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			var got ApkMetadata
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

func TestApkMetadata_Upstream(t *testing.T) {
	tests := []struct {
		name     string
		metadata ApkMetadata
		expected string
	}{
		{
			name: "gocase",
			metadata: ApkMetadata{
				Package: "p",
			},
			expected: "p",
		},
		{
			name: "same package and origin",
			metadata: ApkMetadata{
				Package:       "p",
				OriginPackage: "p",
			},
			expected: "p",
		},
		{
			name: "different package and origin",
			metadata: ApkMetadata{
				Package:       "p",
				OriginPackage: "origin",
			},
			expected: "origin",
		},
		{
			name: "upstream python package information as qualifier",
			metadata: ApkMetadata{
				Package:       "py3-potatoes",
				OriginPackage: "py3-potatoes",
			},
			expected: "potatoes",
		},
		{
			name: "python package with distinct origin package",
			metadata: ApkMetadata{
				Package:       "py3-non-existant",
				OriginPackage: "abcdefg",
			},
			expected: "abcdefg",
		},
		{
			name: "upstream ruby package information as qualifier",
			metadata: ApkMetadata{
				Package:       "ruby-something",
				OriginPackage: "ruby-something",
			},
			expected: "something",
		},
		{
			name: "python package with distinct origin package",
			metadata: ApkMetadata{
				Package:       "ruby-something",
				OriginPackage: "1234567",
			},
			expected: "1234567",
		},
		{
			name: "postgesql-15 upstream postgresql",
			metadata: ApkMetadata{
				Package: "postgresql-15",
			},
			expected: "postgresql",
		},
		{
			name: "postgesql15 upstream postgresql",
			metadata: ApkMetadata{
				Package: "postgresql15",
			},
			expected: "postgresql",
		},
		{
			name: "go-1.19 upstream go",
			metadata: ApkMetadata{
				Package: "go-1.19",
			},
			expected: "go",
		},
		{
			name: "go1.143 upstream go",
			metadata: ApkMetadata{
				Package: "go1.143",
			},
			expected: "go",
		},
		{
			name: "abc-101.191.23456 upstream abc",
			metadata: ApkMetadata{
				Package: "abc-101.191.23456",
			},
			expected: "abc",
		},
		{
			name: "abc101.191.23456 upstream abc",
			metadata: ApkMetadata{
				Package: "abc101.191.23456",
			},
			expected: "abc",
		},
		{
			name: "abc101-12345-1045 upstream abc101-12345",
			metadata: ApkMetadata{
				Package: "abc101-12345-1045",
			},
			expected: "abc101-12345",
		},
		{
			name: "abc101-a12345-1045 upstream abc101-a12345",
			metadata: ApkMetadata{
				Package: "abc101-a12345-1045",
			},
			expected: "abc101-a12345",
		},
		{
			name: "package starting with single digit",
			metadata: ApkMetadata{
				Package: "3proxy",
			},
			expected: "3proxy",
		},
		{
			name: "package starting with multiple digits",
			metadata: ApkMetadata{
				Package: "356proxy",
			},
			expected: "356proxy",
		},
		{
			name: "package composed of only digits",
			metadata: ApkMetadata{
				Package: "123456",
			},
			expected: "123456",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := test.metadata.Upstream()
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
