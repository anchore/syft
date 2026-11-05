package ocaml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOpamFields(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  opamFields
	}{
		{
			name: "name, version and a single license",
			input: `opam-version: "2.0"
name: "lwt"
version: "5.4.2"
license: "MIT"
homepage: "https://github.com/ocsigen/lwt"
`,
			want: opamFields{
				Name:     "lwt",
				Version:  "5.4.2",
				Licenses: []string{"MIT"},
				Homepage: "https://github.com/ocsigen/lwt",
			},
		},
		{
			name: "license list uses opam syntax (no commas)",
			input: `opam-version: "2.0"
license: ["MIT" "ISC"]
`,
			want: opamFields{
				Licenses: []string{"MIT", "ISC"},
			},
		},
		{
			name: "homepage list takes the first entry",
			input: `opam-version: "2.0"
homepage: ["https://a.example" "https://b.example"]
`,
			want: opamFields{
				Homepage: "https://a.example",
			},
		},
		{
			name: "depends with filters, alternatives and exact pins",
			input: `opam-version: "2.0"
depends: [
  "ocaml" {>= "4.08"}
  "dune" {>= "3.9" & build}
  "lwt" {= "5.4.2"}
  "ounit2" {= "2.2.5" & with-test}
  ("ssl" | "tls")
  "mypkg" {= version}
  "odoc" {with-doc}
]
`,
			want: opamFields{
				Depends: []opamDependency{
					{Name: "ocaml"},
					{Name: "dune"},
					{Name: "lwt", Version: "5.4.2"},
					{Name: "ounit2", Version: "2.2.5"},
					{Name: "ssl"},
					{Name: "tls"},
					{Name: "mypkg"},
					{Name: "odoc"},
				},
			},
		},
		{
			name: "url section with single checksum",
			input: `opam-version: "2.0"
url {
  src: "https://example.com/foo-1.0.tbz"
  checksum: "sha256=abc"
}
`,
			want: opamFields{
				URL:       "https://example.com/foo-1.0.tbz",
				Checksums: []string{"sha256=abc"},
			},
		},
		{
			name: "url section with a checksum list",
			input: `opam-version: "2.0"
url {
  src:
    "https://example.com/foo-1.0.tbz"
  checksum: [
    "sha256=abc"
    "sha512=def"
  ]
}
`,
			want: opamFields{
				URL:       "https://example.com/foo-1.0.tbz",
				Checksums: []string{"sha256=abc", "sha512=def"},
			},
		},
		{
			name: "field-like text inside strings and comments is ignored",
			input: `opam-version: "2.0"
# version: "0.0.1"
(* name: "commented" *)
description: """
version: "9.9.9"
license: "GPL"
"""
synopsis: "quoted \" version: \"8.8.8\""
name: "real"
version: "1.0~beta"
`,
			want: opamFields{
				Name:    "real",
				Version: "1.0~beta",
			},
		},
		{
			name: "nested sections and build commands do not leak into fields",
			input: `opam-version: "2.0"
build: [
  ["dune" "subst"] {dev}
  ["dune" "build" "-p" name "-j" jobs]
]
x-ci-accept-failures: ["centos-7"]
extra-source "patch.diff" {
  src: "https://example.com/patch.diff"
  checksum: "md5=00"
}
version: "2.0"
`,
			want: opamFields{
				Version: "2.0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOpamFields([]byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseOpamFields_RejectsNonOpamContent(t *testing.T) {
	_, err := parseOpamFields([]byte("this is not an opam file\n"))
	require.Error(t, err)
}

func TestReadMetadataFile(t *testing.T) {
	data, err := readMetadataFileWithLimit(strings.NewReader("12345"), 5)
	require.NoError(t, err)
	assert.Equal(t, "12345", string(data))

	_, err = readMetadataFileWithLimit(strings.NewReader("123456"), 5)
	require.ErrorIs(t, err, errMetadataFileTooLarge)
}
