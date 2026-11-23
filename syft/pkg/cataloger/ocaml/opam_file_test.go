package ocaml

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/internal/parsing"
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
  "ocamlformat" {= "0.26.2" & with-dev-setup}
  ("alcotest" "qcheck") {with-test}
  "ppx_expect" {with-test | build}
  "base" {= "v0.16.0" | = "v0.17.0"}
  "not-test" {!with-test}
  "not-test-or-doc" {build & !with-doc & !with-test}
  "not-tested" {with-test = false}
  "maybe-test" {?with-test}
]
`,
			want: opamFields{
				Depends: []opamDependency{
					{Name: "ocaml"},
					{Name: "dune"},
					{Name: "lwt", Version: "5.4.2"},
					{Name: "ounit2", Version: "2.2.5", Development: true},
					{Name: "ssl"},
					{Name: "tls"},
					{Name: "mypkg"},
					{Name: "odoc", Development: true},
					{Name: "ocamlformat", Version: "0.26.2", Development: true},
					{Name: "alcotest", Development: true},
					{Name: "qcheck", Development: true},
					// a disjunction can hold without with-test
					{Name: "ppx_expect"},
					// a choice of versions is not a pin
					{Name: "base"},
					// needed when not testing, documenting or developing
					{Name: "not-test"},
					{Name: "not-test-or-doc"},
					{Name: "not-tested"},
					{Name: "maybe-test"},
				},
			},
		},
		{
			name: "escape sequences",
			input: "opam-version: \"2.0\"\n" +
				`name: "a\"b\\c"` + "\n" +
				`version: "1\n2\t3\0654\x35"` + "\n" +
				"homepage: \"https://example.com/\\\n    long\"\n" +
				`license: """M"I"T\q"""` + "\n",
			want: opamFields{
				Name:     `a"b\c`,
				Version:  "1\n2\t3A45",
				Homepage: "https://example.com/long",
				// unknown escapes are kept as written
				Licenses: []string{`M"I"T\q`},
			},
		},
		{
			name:  "byte order mark",
			input: "\uFEFFopam-version: \"2.0\"\nversion: \"1.0\"\n",
			want: opamFields{
				Version: "1.0",
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

func TestParseOpamFields_NestingDepth(t *testing.T) {
	nest := func(open, inner, closing string, depth int) string {
		return strings.Repeat(open, depth) + inner + strings.Repeat(closing, depth)
	}
	tests := []struct {
		name  string
		input func(depth int) string
	}{
		{
			name:  "lists",
			input: func(depth int) string { return "license: " + nest("[", `"MIT"`, "]", depth) },
		},
		{
			name:  "groups",
			input: func(depth int) string { return "depends: " + nest("(", `"lwt"`, ")", depth) },
		},
		{
			name:  "options",
			input: func(depth int) string { return "depends: " + nest(`"lwt" {`, `"x"`, "}", depth) },
		},
		{
			name:  "sections",
			input: func(depth int) string { return nest("s {\n", `x: "y"`, "\n}", depth) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseOpamFields([]byte("opam-version: \"2.0\"\n" + tt.input(parsing.MaxDepth)))
			require.NoError(t, err)

			_, err = parseOpamFields([]byte("opam-version: \"2.0\"\n" + tt.input(parsing.MaxDepth+1)))
			require.ErrorIs(t, err, errTooDeep)
		})
	}
}

func TestParseOpamFields_DeepInput(t *testing.T) {
	// deep input overflowed the goroutine stack (fatal, not recoverable) before nesting was bounded
	_, err := parseOpamFields([]byte("opam-version: \"2.0\"\nlicense: " + strings.Repeat("[", 2<<20)))
	require.ErrorIs(t, err, errTooDeep)
}

func TestParseSwitchState(t *testing.T) {
	installed, err := parseSwitchState([]byte("opam-version: \"2.0\"\ncompiler: [\"ocaml.5.3.0\"]\ninstalled: [\"lwt.5.4.2\" \"ocaml.5.3.0\"]\n"))
	require.NoError(t, err)
	assert.Equal(t, []string{"lwt.5.4.2", "ocaml.5.3.0"}, installed)

	_, err = parseSwitchState([]byte("opam-version: \"2.0\"\n"))
	require.Error(t, err)
}

func TestReadOpamFields_SizeLimit(t *testing.T) {
	// the parser costs far more memory than the size of its input, so opam files have a limit of their own
	content := "opam-version: \"2.0\"\nx-pad: \"" + strings.Repeat("a", maxOpamFileSize) + "\"\n"
	require.Greater(t, len(content), maxOpamFileSize)
	_, ok := readOpamFields(strings.NewReader(content))
	assert.False(t, ok)

	_, ok = readOpamFields(strings.NewReader("opam-version: \"2.0\"\n"))
	assert.True(t, ok)
}

func TestReadMetadataFile(t *testing.T) {
	data, err := readMetadataFileWithLimit(strings.NewReader("12345"), 5)
	require.NoError(t, err)
	assert.Equal(t, "12345", string(data))

	_, err = readMetadataFileWithLimit(strings.NewReader("123456"), 5)
	require.ErrorIs(t, err, errMetadataFileTooLarge)
}
