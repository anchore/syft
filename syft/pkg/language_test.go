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
	}

	var languages []string
	var expectedLanguages = strset.New()
	for _, ty := range AllLanguages {
		expectedLanguages.Add(string(ty))
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			actual := LanguageFromPURL(tt.purl)

			if actual != "" {
				languages = append(languages, string(actual))
			}

			assert.Equalf(t, tt.want, actual, "LanguageFromPURL(%v)", tt.purl)
		})
	}

	assert.ElementsMatch(t, expectedLanguages.List(), languages, "missing one or more languages to test against (maybe a package type was added?)")

}
