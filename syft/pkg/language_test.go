package pkg

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
)

func TestLanguageFromPURL(t *testing.T) {

	tests := []struct {
		purl string
		want Language
	}{

		{
			purl: "pkg:npm/util@2.32",
			want: JavaScript,
		},
		{
			purl: "pkg:pypi/util-linux@2.32.1-27.el8",
			want: Python,
		},
		{
			purl: "pkg:gem/ruby-advisory-db-check@0.12.4",
			want: Ruby,
		},
		{
			purl: "pkg:golang/github.com/gorilla/context@234fd47e07d1004f0aed9c",
			want: Go,
		},
		{
			purl: "pkg:pub/util@1.2.34",
			want: Dart,
		},
		{
			purl: "pkg:dotnet/Microsoft.CodeAnalysis.Razor@2.2.0",
			want: Dotnet,
		},
		{
			purl: "pkg:nuget/Newtonsoft.Json@13.0.0",
			want: Dotnet,
		},
		{
			purl: "pkg:cargo/clap@2.33.0",
			want: Rust,
		},
		{
			purl: "pkg:composer/laravel/laravel@5.5.0",
			want: PHP,
		},
		{
			purl: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=zip&classifier=dist",
			want: Java,
		},
		{
			purl: "pkg:cocoapods/GlossButtonNode@3.1.2",
			want: Swift,
		},
		{
			purl: "pkg:conan/catch2@2.13.8",
			want: CPP,
		},
		{
			purl: "pkg:hackage/HTTP@4000.3.16",
			want: Haskell,
		},
		{
			purl: "pkg:hex/hpax/hpax@0.1.1",
			want: UnknownLanguage,
		},
		{
			purl: "pkg:cran/base@4.3.0",
			want: R,
		},
		{
			purl: "pkg:swift/github.com/apple/swift-numerics/swift-numerics@1.0.2",
			want: Swift,
		},
		{
			purl: "pkg:swiplpack/conditon@0.1.1",
			want: Swipl,
		},
		{
			purl: "pkg:luarocks/kong@3.7.0",
			want: Lua,
		},
		{
			purl: "pkg:opam/ocaml-base-compiler@5.2.0",
			want: OCaml,
		},
	}

	var languages = strset.New()
	var expectedLanguages = strset.New()
	for _, ty := range AllLanguages {
		expectedLanguages.Add(string(ty))
	}

	// we cannot determine the language from these purl ecosystems (yet?)
	expectedLanguages.Remove(Elixir.String())
	expectedLanguages.Remove(Erlang.String())

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			actual := LanguageFromPURL(tt.purl)

			if actual != "" {
				languages.Add(string(actual))
			}

			assert.Equalf(t, tt.want, actual, "LanguageFromPURL(%v)", tt.purl)
		})
	}

	assert.ElementsMatch(t, expectedLanguages.List(), languages.List(), "missing one or more languages to test against (maybe a package type was added?)")

}

func TestLanguageByName(t *testing.T) {
	tests := []struct {
		name     string
		language Language
	}{
		{
			name:     "maven",
			language: Java,
		},
		{
			name:     "java",
			language: Java,
		},
		{
			name:     "java-archive",
			language: Java,
		},
		{
			name:     "java",
			language: Java,
		},
		{
			name:     "composer",
			language: PHP,
		},
		{
			name:     "php-composer",
			language: PHP,
		},
		{
			name:     "php",
			language: PHP,
		},
		{
			name:     "go",
			language: Go,
		},
		{
			name:     "golang",
			language: Go,
		},
		{
			name:     "go-module",
			language: Go,
		},
		{
			name:     "npm",
			language: JavaScript,
		},
		{
			name:     "javascript",
			language: JavaScript,
		},
		{
			name:     "node.js",
			language: JavaScript,
		},
		{
			name:     "nodejs",
			language: JavaScript,
		},
		{
			name:     "pypi",
			language: Python,
		},
		{
			name:     "python",
			language: Python,
		},
		{
			name:     "gem",
			language: Ruby,
		},
		{
			name:     "ruby",
			language: Ruby,
		},
		{
			name:     "rust",
			language: Rust,
		},
		{
			name:     "rust-crate",
			language: Rust,
		},
		{
			name:     "cargo",
			language: Rust,
		},
		{
			name:     "dart",
			language: Dart,
		},
		{
			name:     "dart-pub",
			language: Dart,
		},
		{
			name:     "pub",
			language: Dart,
		},
		{
			name:     "dotnet",
			language: Dotnet,
		},
		{
			name:     "swift",
			language: Swift,
		},
		{
			name:     "swiplpack",
			language: Swipl,
		},
		{
			name:     "opam",
			language: OCaml,
		},
		{
			name:     "pod",
			language: Swift,
		},
		{
			name:     "cocoapods",
			language: Swift,
		},
		{
			name:     "unknown",
			language: UnknownLanguage,
		},
		{
			name:     "conan",
			language: CPP,
		},
		{
			name:     "c++",
			language: CPP,
		},
		{
			name:     "hackage",
			language: Haskell,
		},
		{
			name:     "haskell",
			language: Haskell,
		},
		{
			name:     "R",
			language: R,
		},
	}

	for _, test := range tests {
		assert.Equal(t, LanguageByName(test.name), test.language)
	}
}
