package perl

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_parsePerllocal(t *testing.T) {
	// two stanzas as ExtUtils::MakeMaker writes them, with the second module upgraded in place so both a
	// stale entry and a current one are present. Real EUMM emits =head2; the =head1 here is a deliberate
	// variation, to pin that the parser keys on the C<Module> marker and not on the heading level.
	const pod = `=head0 L<Perl documentation|perl>

=head1 Sun Jul 26 18:04:12 2026: C<Module> L<Encode|Encode>

=over 4

=item *

C<installed into: /usr/local/lib/perl5/site_perl/5.40.4>

=item *

C<LINKTYPE: dynamic>

=item *

C<VERSION: 3.24>

=item *

C<EXE_FILES: bin/enc2xs>

=back

=head2 Mon Jul 27 20:10:38 2026: C<Module> L<Net::HTTP|Net::HTTP>

=over 4

=item *

C<installed into: /usr/local/lib/perl5/site_perl/5.40.4>

=item *

C<VERSION: 6.24>

=back
`

	assert.Equal(t, []perllocalEntry{
		{Module: "Encode", InstalledInto: "/usr/local/lib/perl5/site_perl/5.40.4", Version: "3.24"},
		{Module: "Net::HTTP", InstalledInto: "/usr/local/lib/perl5/site_perl/5.40.4", Version: "6.24"},
	}, parsePerllocal(strings.NewReader(pod)))
}

func Test_parsePerllocal_degrades(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{name: "empty", contents: ""},
		{name: "no module stanzas", contents: "=head0 L<Perl documentation|perl>\n"},
		// a stanza body with no C<Module> heading before it has nothing to attach to
		{name: "orphaned body", contents: "=item *\n\nC<VERSION: 1.00>\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Empty(t, parsePerllocal(strings.NewReader(tt.contents)))
		})
	}
}

func Test_perllocalVersion(t *testing.T) {
	pods := []perllocalPod{
		{
			location: file.NewLocation("/usr/local/lib/perl5/5.40.4/aarch64-linux-gnu/perllocal.pod"),
			entries: []perllocalEntry{
				{Module: "Net::HTTP", InstalledInto: "/usr/local/lib/perl5/site_perl/5.40.4", Version: "6.24"},
				// the file is append-only, so an upgrade leaves the earlier stanza in place forever
				{Module: "Text::CSV", InstalledInto: "/usr/local/lib/perl5/site_perl/5.40.4", Version: "2.02"},
				{Module: "Text::CSV", InstalledInto: "/usr/local/lib/perl5/site_perl/5.40.4", Version: "2.06"},
				// a stanza whose libdir belongs to another install tree entirely
				{Module: "JSON::PP", InstalledInto: "/opt/perl-5.36.0/lib/perl5/site_perl/5.36.0", Version: "2.27300"},
				// an INSTALL_BASE install and a local::lib nested inside it both prefix-match one packlist
				{Module: "Try::Tiny", InstalledInto: "/opt/app/lib/perl5", Version: "0.30"},
				{Module: "Try::Tiny", InstalledInto: "/opt/app/lib/perl5/local", Version: "0.32"},
				{Module: "Carp", InstalledInto: "/usr/local/lib/perl5/site_perl/5.40.4"},
			},
		},
	}

	tests := []struct {
		name         string
		dashedName   string
		packlistPath string
		want         string
	}{
		{
			name:         "module name dashes to the packlist name",
			dashedName:   "Net-HTTP",
			packlistPath: "/usr/local/lib/perl5/site_perl/5.40.4/aarch64-linux-gnu/auto/Net/HTTP/.packlist",
			want:         "6.24",
		},
		{
			name:         "the last stanza wins over a stale one",
			dashedName:   "Text-CSV",
			packlistPath: "/usr/local/lib/perl5/site_perl/5.40.4/aarch64-linux-gnu/auto/Text/CSV/.packlist",
			want:         "2.06",
		},
		{
			// without the libdir rule the other perl's version would silently win, which is worse than
			// reporting no version at all
			name:         "a stanza from another install tree is not used",
			dashedName:   "JSON-PP",
			packlistPath: "/usr/local/lib/perl5/site_perl/5.40.4/aarch64-linux-gnu/auto/JSON/PP/.packlist",
			want:         "",
		},
		{
			name:         "the longest matching libdir wins",
			dashedName:   "Try-Tiny",
			packlistPath: "/opt/app/lib/perl5/local/aarch64-linux-gnu/auto/Try/Tiny/.packlist",
			want:         "0.32",
		},
		{
			name:         "the outer libdir still matches its own packlist",
			dashedName:   "Try-Tiny",
			packlistPath: "/opt/app/lib/perl5/aarch64-linux-gnu/auto/Try/Tiny/.packlist",
			want:         "0.30",
		},
		{
			// a directory scan reports paths relative to its root while perllocal records absolute libdirs
			name:         "relative packlist path from a directory scan",
			dashedName:   "Net-HTTP",
			packlistPath: "usr/local/lib/perl5/site_perl/5.40.4/aarch64-linux-gnu/auto/Net/HTTP/.packlist",
			want:         "6.24",
		},
		{
			name:         "no stanza for this distribution",
			dashedName:   "IO-Socket-SSL",
			packlistPath: "/usr/local/lib/perl5/site_perl/5.40.4/aarch64-linux-gnu/auto/IO/Socket/SSL/.packlist",
			want:         "",
		},
		{
			name:         "a stanza with no VERSION is not a match",
			dashedName:   "Carp",
			packlistPath: "/usr/local/lib/perl5/site_perl/5.40.4/aarch64-linux-gnu/auto/Carp/.packlist",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, evidence := perllocalVersion(pods, tt.dashedName, tt.packlistPath)
			assert.Equal(t, tt.want, version)
			if tt.want == "" {
				assert.Nil(t, evidence)
				return
			}
			require.NotNil(t, evidence)
			assert.Equal(t, "/usr/local/lib/perl5/5.40.4/aarch64-linux-gnu/perllocal.pod", evidence.Path())
		})
	}
}
