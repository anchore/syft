package perl

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_distNameFromPacklistPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux/auto/Text/CSV/.packlist", want: "Text-CSV"},
		{path: "/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux/auto/IO/Socket/SSL/.packlist", want: "IO-Socket-SSL"},
		{path: "auto/URI/.packlist", want: "URI"},
		// the perl core install has a packlist with no auto/ segment; it must produce nothing
		{path: "/usr/local/lib/perl5/5.40.4/x86_64-linux/.packlist", want: ""},
		{path: "/some/auto/.packlist", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, distNameFromPacklistPath(tt.path))
		})
	}
}

func Test_mainModuleFile(t *testing.T) {
	files := []string{
		"/usr/local/lib/perl5/site_perl/5.40.4/Text/CSV_PP.pm",
		"/usr/local/lib/perl5/site_perl/5.40.4/Text/CSV.pm",
	}

	assert.Equal(t, "/usr/local/lib/perl5/site_perl/5.40.4/Text/CSV.pm", mainModuleFile("Text-CSV", files))
	assert.Equal(t, "", mainModuleFile("Text-CSV-XS", files))
}

func Test_versionFromPM(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		want     string
	}{
		{name: "our, single quoted", contents: "package Text::CSV;\n\nour $VERSION = '2.06';\n", want: "2.06"},
		// what Text::CSV and JSON::PP really do: use vars, then assign inside a BEGIN block
		{name: "assigned inside BEGIN", contents: "use vars qw( $VERSION );\n\nBEGIN {\n    $VERSION = '2.06';\n}\n", want: "2.06"},
		{name: "bare assignment", contents: "$VERSION = \"1.303\";\n", want: "1.303"},
		{name: "unquoted decimal", contents: "our $VERSION = 5.35;\n", want: "5.35"},
		{name: "v-string is preserved", contents: "our $VERSION = 'v1.1.4';\n", want: "v1.1.4"},
		// the fully qualified form older Dist::Zilla wrote, as real JSON::PP 2.27300 carries
		{name: "package qualified", contents: "package JSON::PP;\n\n$JSON::PP::VERSION = '2.27300';\n", want: "2.27300"},
		{name: "qv wrapper", contents: "our $VERSION = qv('1.2.3');\n", want: "1.2.3"},
		// perl 5.12 and later allow the version in the package statement, and a distribution using it
		// need carry no $VERSION at all
		{name: "package statement v-string", contents: "package CPAN::02Packages::Search v1.0.0;\nuse v5.24;\n", want: "v1.0.0"},
		{name: "package statement decimal", contents: "package Foo::Bar 1.23;\n", want: "1.23"},
		{name: "package statement block form", contents: "package Foo::Bar v2.0.1 {\n}\n", want: "v2.0.1"},
		// a $VERSION assignment later in the file still wins over a version-less package statement
		{name: "package statement without a version", contents: "package Foo::Bar;\nour $VERSION = '1.00';\n", want: "1.00"},
		// $XS_VERSION and friends must not be mistaken for $VERSION
		{name: "other version variables ignored", contents: "our $XS_VERSION = '9.99';\nour $VERSION = '1.00';\n", want: "1.00"},
		// real Encode.pm: declared bare, then computed from an RCS keyword inside BEGIN. Nothing static can
		// read that, and guessing at it would be worse than the empty version perllocal.pod then fills in.
		{name: "computed from an RCS Revision keyword", contents: "our $VERSION;\nBEGIN {\n    $VERSION = sprintf \"%d.%02d\", q$Revision: 3.24 $ =~ /(\\d+)/g;\n}\n", want: ""},
		{name: "no version at all", contents: "package Foo;\n1;\n", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, versionFromPM(strings.NewReader(tt.contents)))
		})
	}
}

// Test_parsePacklist_metadataSuffix pins the cut against what ExtUtils::Packlist::read does, which is to
// strip a suffix matching /^(.*?)( \w+=.*)$/ rather than to cut at the first space. A perl tree under a
// directory whose name contains a space is ordinary on macOS and Windows.
func Test_parsePacklist_metadataSuffix(t *testing.T) {
	const packlist = `/usr/local/lib/perl5/site_perl/5.40.4/Text/CSV.pm
/Users/me/My Perl/lib/Text/CSV_PP.pm
/usr/local/lib/perl5/site_perl/5.40.4/auto/Text/CSV/CSV.so type=file
/usr/local/bin/csvdiff type=link from=/usr/local/bin/csvdiff-2.06
`

	pkgs, _, err := parsePacklist(context.Background(), nil, nil,
		file.NewLocationReadCloser(file.NewLocation("usr/local/lib/perl5/site_perl/5.40.4/aarch64-linux-gnu/auto/Text/CSV/.packlist"),
			io.NopCloser(strings.NewReader(packlist))))
	require.NoError(t, err)
	require.Len(t, pkgs, 1)

	assert.Equal(t, []string{
		"/usr/local/lib/perl5/site_perl/5.40.4/Text/CSV.pm",
		"/Users/me/My Perl/lib/Text/CSV_PP.pm",
		"/usr/local/lib/perl5/site_perl/5.40.4/auto/Text/CSV/CSV.so",
		"/usr/local/bin/csvdiff",
	}, pkgs[0].Metadata.(pkg.CpanDistribution).Files)
}
