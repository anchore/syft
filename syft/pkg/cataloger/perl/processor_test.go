package perl

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_mergeDistributions(t *testing.T) {
	fromInstallJSON := newCpanPackage("URI", "5.35", "OALDERS",
		pkg.CpanDistribution{
			Dist:    "URI-5.35",
			Author:  "OALDERS",
			Path:    "O/OA/OALDERS/URI-5.35.tar.gz",
			Modules: []pkg.CpanModule{{Name: "URI", Version: "5.35"}},
		},
		[]pkg.License{pkg.NewLicenseWithContext(context.Background(), "perl_5")},
		file.NewLocation("/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux/.meta/URI-5.35/install.json"),
	)

	fromPacklist := newCpanPackage("URI", "5.35", "", pkg.CpanDistribution{MainModule: "URI"}, nil,
		file.NewLocation("/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux/auto/URI/.packlist"),
	)

	otherVersion := newCpanPackage("URI", "5.34", "", pkg.CpanDistribution{MainModule: "URI"}, nil,
		file.NewLocation("/opt/lib/perl5/x86_64-linux/auto/URI/.packlist"),
	)

	// the packlist arriving first must not change which package wins
	for _, order := range [][]pkg.Package{
		{fromInstallJSON, fromPacklist, otherVersion},
		{fromPacklist, fromInstallJSON, otherVersion},
	} {
		merged, _, err := mergeDistributions(order, nil, nil)
		require.NoError(t, err)
		require.Len(t, merged, 2)

		uri := merged[0]
		assert.Equal(t, "5.35", uri.Version)
		assert.Equal(t, "pkg:cpan/URI@5.35?author=OALDERS", uri.PURL)
		assert.Equal(t, "OALDERS", uri.Metadata.(pkg.CpanDistribution).Author)
		assert.Len(t, uri.Licenses.ToSlice(), 1)
		assert.Len(t, uri.Locations.ToSlice(), 2, "the packlist should be kept as additional evidence")

		// a different version of the same distribution is a different package
		assert.Equal(t, "5.34", merged[1].Version)
	}
}

// a packlist lives at auto/<Module>/.packlist, so for any distribution whose main module is named
// differently from the distribution the two kinds of evidence never share a (name, version) key.
// libwww-perl is the canonical case: auto/LWP/.packlist against the distribution libwww-perl.
func Test_mergeDistributions_packlistNamedAfterModule(t *testing.T) {
	fromInstallJSON := newCpanPackage("libwww-perl", "5.836", "GAAS",
		pkg.CpanDistribution{
			Dist:    "libwww-perl-5.836",
			Author:  "GAAS",
			Path:    "G/GA/GAAS/libwww-perl-5.836.tar.gz",
			Modules: []pkg.CpanModule{{Name: "LWP", Version: "5.836"}, {Name: "LWP::UserAgent", Version: "5.834"}},
		},
		nil,
		file.NewLocation("/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux/.meta/libwww-perl-5.836/install.json"),
	)

	fromPacklist := newCpanPackage("LWP", "5.836", "", pkg.CpanDistribution{MainModule: "LWP"}, nil,
		file.NewLocation("/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux/auto/LWP/.packlist"),
	)

	// a packlist whose version could not be read still belongs to the distribution providing it
	versionless := newCpanPackage("LWP-UserAgent", "", "", pkg.CpanDistribution{MainModule: "LWP::UserAgent"}, nil,
		file.NewLocation("/usr/local/lib/perl5/site_perl/5.40.4/x86_64-linux/auto/LWP/UserAgent/.packlist"),
	)

	// the same module installed into a second lib tree is a second install, and the module index is
	// scoped to a tree so that it cannot be claimed by the distribution in the first one
	otherTree := newCpanPackage("LWP", "5.836", "", pkg.CpanDistribution{MainModule: "LWP"}, nil,
		file.NewLocation("/opt/lib/perl5/x86_64-linux/auto/LWP/.packlist"),
	)

	for _, order := range [][]pkg.Package{
		{fromInstallJSON, fromPacklist, versionless, otherTree},
		{otherTree, versionless, fromPacklist, fromInstallJSON},
	} {
		merged, _, err := mergeDistributions(order, nil, nil)
		require.NoError(t, err)
		require.Len(t, merged, 2, "the same tree's module-named packlists belong to libwww-perl, the other tree's does not")

		assert.Equal(t, "libwww-perl", merged[0].Name)
		assert.Equal(t, "pkg:cpan/libwww-perl@5.836?author=GAAS", merged[0].PURL)
		assert.Len(t, merged[0].Locations.ToSlice(), 3)

		assert.Equal(t, "LWP", merged[1].Name)
		assert.Equal(t, []string{"/opt/lib/perl5/x86_64-linux/auto/LWP/.packlist"}, realPaths(merged[1]))
	}
}
