package dotnet

import (
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		cataloger pkg.Cataloger
		expected  []string
	}{
		{
			name:      "obtain deps.json files",
			fixture:   "test-fixtures/glob-paths",
			cataloger: NewDotnetDepsCataloger(),
			expected: []string{
				"src/something.deps.json",
			},
		},
		{
			name:      "obtain portable executable files",
			fixture:   "test-fixtures/glob-paths",
			cataloger: NewDotnetPortableExecutableCataloger(),
			expected: []string{
				"src/something.dll",
				"src/something.exe",
			},
		},
		{
			name:      "obtain combined files",
			fixture:   "test-fixtures/glob-paths",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expected: []string{
				"src/something.deps.json",
				"src/something.dll",
				"src/something.exe",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, test.cataloger)
		})
	}
}

func TestCataloger(t *testing.T) {

	net8AppExpectedDepPkgsWithoutUnpairedDlls := []string{
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.af @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ar @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.az @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.bg @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.bn-BD @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.cs @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.da @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.de @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.el @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.es @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fa @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fi-FI @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fr-BE @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.he @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.hr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.hu @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.hy @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.id @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.is @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.it @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ja @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ko-KR @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ku @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.lv @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ms-MY @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.mt @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.nb @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.nb-NO @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.nl @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.pl @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.pt @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ro @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ru @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sk @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sl @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sr-Latn @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sv @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.th-TH @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.tr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.uk @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.uz-Cyrl-UZ @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.uz-Latn-UZ @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.vi @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.zh-CN @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.zh-Hans @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.zh-Hant @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Newtonsoft.Json @ 13.0.3 (/app/dotnetapp.deps.json)",
		"dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
	}
	// app packages (from deps.json)
	net8AppExpectedDepPkgs := []string{
		"Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
	}
	net8AppExpectedDepPkgs = append(net8AppExpectedDepPkgs, net8AppExpectedDepPkgsWithoutUnpairedDlls...)

	var net8AppExpectedDepPkgsWithRuntime []string
	net8AppExpectedDepPkgsWithRuntime = append(net8AppExpectedDepPkgsWithRuntime, net8AppExpectedDepPkgs...)
	net8AppExpectedDepPkgsWithRuntime = append(net8AppExpectedDepPkgsWithRuntime, "Microsoft.NETCore.App.Runtime.linux-x64 @ 8.0.14 (/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.14/Microsoft.NETCore.App.deps.json)")

	// app binaries (always dlls)
	net8AppBinaryOnlyPkgs := []string{
		"Humanizer @ 2.14.1.48190 (/app/Humanizer.dll)",
		"Humanizer @ 2.14.1.48190 (/app/af/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/ar/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/az/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/bg/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/bn-BD/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/cs/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/da/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/de/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/el/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/es/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/fa/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/fi-FI/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/fr-BE/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/fr/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/he/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/hr/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/hu/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/hy/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/id/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/is/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/it/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/ja/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/ku/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/lv/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/nb-NO/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/nb/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/nl/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/pl/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/pt/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/ro/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/ru/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/sk/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/sl/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/sr-Latn/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/sr/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/sv/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/tr/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/uk/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/uz-Cyrl-UZ/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/uz-Latn-UZ/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/vi/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/zh-CN/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/zh-Hans/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/zh-Hant/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/ko-KR/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/ms-MY/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/mt/Humanizer.resources.dll)",
		"Humanizer @ 2.14.1.48190 (/app/th-TH/Humanizer.resources.dll)",
		"Json.NET @ 13.0.3.27908 (/app/Newtonsoft.Json.dll)",
		"dotnetapp @ 1.0.0.0 (/app/dotnetapp.dll)",
	}

	// app relationships (from deps.json)
	net8AppDepOnlyRelationshipsWithoutHumanizer := []string{
		"Humanizer.Core.af @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ar @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.az @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.bg @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.bn-BD @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.cs @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.da @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.de @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.el @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.es @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fa @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fi-FI @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.fr-BE @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.he @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.hr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.hu @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.hy @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.id @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.is @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.it @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ja @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ko-KR @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ku @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.lv @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ms-MY @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.mt @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.nb @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.nb-NO @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.nl @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.pl @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.pt @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ro @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.ru @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sk @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sl @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sr-Latn @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.sv @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.th-TH @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.tr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.uk @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.uz-Cyrl-UZ @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.uz-Latn-UZ @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.vi @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.zh-CN @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.zh-Hans @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core.zh-Hant @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.af @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ar @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.az @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.bg @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.bn-BD @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.cs @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.da @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.de @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.el @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.es @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fa @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fi-FI @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fr-BE @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.he @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.hr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.hu @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.hy @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.id @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.is @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.it @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ja @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ko-KR @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ku @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.lv @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ms-MY @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.mt @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.nb @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.nb-NO @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.nl @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.pl @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.pt @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ro @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ru @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sk @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sl @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sr-Latn @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sv @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.th-TH @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.tr @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.uk @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.uz-Cyrl-UZ @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.uz-Latn-UZ @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.vi @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.zh-CN @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.zh-Hans @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.zh-Hant @ 2.14.1 (/app/dotnetapp.deps.json)",
		"Newtonsoft.Json @ 13.0.3 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
	}

	var net8AppDepOnlyRelationships []string
	humanizerToAppDepsRelationship := "Humanizer @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)"
	net8AppDepOnlyRelationships = append(net8AppDepOnlyRelationships, net8AppDepOnlyRelationshipsWithoutHumanizer...)
	net8AppDepOnlyRelationships = append(net8AppDepOnlyRelationships, humanizerToAppDepsRelationship)

	var net8AppDepOnlyRelationshipsWithRuntime []string
	net8AppDepOnlyRelationshipsWithRuntime = append(net8AppDepOnlyRelationshipsWithRuntime, net8AppDepOnlyRelationships...)
	net8AppDepOnlyRelationshipsWithRuntime = append(net8AppDepOnlyRelationshipsWithRuntime,
		"Microsoft.NETCore.App.Runtime.linux-x64 @ 8.0.14 (/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.14/Microsoft.NETCore.App.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
	)

	var net8AppExpectedDepRelationships []string
	net8AppExpectedDepRelationships = append(net8AppExpectedDepRelationships, net8AppDepOnlyRelationships...)

	var net8AppExpectedDepSelfContainedPkgs []string
	net8AppExpectedDepSelfContainedPkgs = append(net8AppExpectedDepSelfContainedPkgs, net8AppExpectedDepPkgs...)
	net8AppExpectedDepSelfContainedPkgs = append(net8AppExpectedDepSelfContainedPkgs,
		// add the CLR runtime packages...
		"runtimepack.Microsoft.NETCore.App.Runtime.win-x64 @ 8.0.14 (/app/dotnetapp.deps.json)",
	)

	var net8AppExpectedDepsSelfContainedPkgs []string
	net8AppExpectedDepsSelfContainedPkgs = append(net8AppExpectedDepsSelfContainedPkgs, net8AppExpectedDepPkgs...)
	net8AppExpectedDepsSelfContainedPkgs = append(net8AppExpectedDepsSelfContainedPkgs,
		// add the CLR runtime packages...
		"runtimepack.Microsoft.NETCore.App.Runtime.win-x64 @ 8.0.14 (/app/dotnetapp.deps.json)",
	)

	var net8AppExpectedDepSelfContainedRelationships []string
	net8AppExpectedDepSelfContainedRelationships = append(net8AppExpectedDepSelfContainedRelationships, net8AppDepOnlyRelationships...)
	net8AppExpectedDepSelfContainedRelationships = append(net8AppExpectedDepSelfContainedRelationships,
		// add the CLR runtime relationships...
		"runtimepack.Microsoft.NETCore.App.Runtime.win-x64 @ 8.0.14 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
	)

	var net8AppExpectedBinarySelfContainedPkgs []string
	net8AppExpectedBinarySelfContainedPkgs = append(net8AppExpectedBinarySelfContainedPkgs, net8AppBinaryOnlyPkgs...)
	net8AppExpectedBinarySelfContainedPkgs = append(net8AppExpectedBinarySelfContainedPkgs,
		// include the runtime...
		".NET Runtime @ 8,0,1425,11118 (/app/coreclr.dll)",
		"Microsoft.CSharp @ 8.0.1425.11118 (/app/Microsoft.CSharp.dll)",
		"Microsoft.VisualBasic @ 8.0.1425.11118 (/app/Microsoft.VisualBasic.dll)",
		"Microsoft.VisualBasic.Core @ 13.0.1425.11118 (/app/Microsoft.VisualBasic.Core.dll)",
		"Microsoft.Win32.Primitives @ 8.0.1425.11118 (/app/Microsoft.Win32.Primitives.dll)",
		"Microsoft.Win32.Registry @ 8.0.1425.11118 (/app/Microsoft.Win32.Registry.dll)",
		"System @ 8.0.1425.11118 (/app/System.dll)",
		"System.AppContext @ 8.0.1425.11118 (/app/System.AppContext.dll)",
		"System.Buffers @ 8.0.1425.11118 (/app/System.Buffers.dll)",
		"System.Collections @ 8.0.1425.11118 (/app/System.Collections.dll)",
		"System.Collections.Concurrent @ 8.0.1425.11118 (/app/System.Collections.Concurrent.dll)",
		"System.Collections.Immutable @ 8.0.1425.11118 (/app/System.Collections.Immutable.dll)",
		"System.Collections.NonGeneric @ 8.0.1425.11118 (/app/System.Collections.NonGeneric.dll)",
		"System.Collections.Specialized @ 8.0.1425.11118 (/app/System.Collections.Specialized.dll)",
		"System.ComponentModel @ 8.0.1425.11118 (/app/System.ComponentModel.dll)",
		"System.ComponentModel.Annotations @ 8.0.1425.11118 (/app/System.ComponentModel.Annotations.dll)",
		"System.ComponentModel.DataAnnotations @ 8.0.1425.11118 (/app/System.ComponentModel.DataAnnotations.dll)",
		"System.ComponentModel.EventBasedAsync @ 8.0.1425.11118 (/app/System.ComponentModel.EventBasedAsync.dll)",
		"System.ComponentModel.Primitives @ 8.0.1425.11118 (/app/System.ComponentModel.Primitives.dll)",
		"System.ComponentModel.TypeConverter @ 8.0.1425.11118 (/app/System.ComponentModel.TypeConverter.dll)",
		"System.Configuration @ 8.0.1425.11118 (/app/System.Configuration.dll)",
		"System.Console @ 8.0.1425.11118 (/app/System.Console.dll)",
		"System.Core @ 8.0.1425.11118 (/app/System.Core.dll)",
		"System.Data @ 8.0.1425.11118 (/app/System.Data.dll)",
		"System.Data.Common @ 8.0.1425.11118 (/app/System.Data.Common.dll)",
		"System.Data.DataSetExtensions @ 8.0.1425.11118 (/app/System.Data.DataSetExtensions.dll)",
		"System.Diagnostics.Contracts @ 8.0.1425.11118 (/app/System.Diagnostics.Contracts.dll)",
		"System.Diagnostics.Debug @ 8.0.1425.11118 (/app/System.Diagnostics.Debug.dll)",
		"System.Diagnostics.DiagnosticSource @ 8.0.1425.11118 (/app/System.Diagnostics.DiagnosticSource.dll)",
		"System.Diagnostics.FileVersionInfo @ 8.0.1425.11118 (/app/System.Diagnostics.FileVersionInfo.dll)",
		"System.Diagnostics.Process @ 8.0.1425.11118 (/app/System.Diagnostics.Process.dll)",
		"System.Diagnostics.StackTrace @ 8.0.1425.11118 (/app/System.Diagnostics.StackTrace.dll)",
		"System.Diagnostics.TextWriterTraceListener @ 8.0.1425.11118 (/app/System.Diagnostics.TextWriterTraceListener.dll)",
		"System.Diagnostics.Tools @ 8.0.1425.11118 (/app/System.Diagnostics.Tools.dll)",
		"System.Diagnostics.TraceSource @ 8.0.1425.11118 (/app/System.Diagnostics.TraceSource.dll)",
		"System.Diagnostics.Tracing @ 8.0.1425.11118 (/app/System.Diagnostics.Tracing.dll)",
		"System.Drawing @ 8.0.1425.11118 (/app/System.Drawing.dll)",
		"System.Drawing.Primitives @ 8.0.1425.11118 (/app/System.Drawing.Primitives.dll)",
		"System.Dynamic.Runtime @ 8.0.1425.11118 (/app/System.Dynamic.Runtime.dll)",
		"System.Formats.Asn1 @ 8.0.1425.11118 (/app/System.Formats.Asn1.dll)",
		"System.Formats.Tar @ 8.0.1425.11118 (/app/System.Formats.Tar.dll)",
		"System.Globalization @ 8.0.1425.11118 (/app/System.Globalization.dll)",
		"System.Globalization.Calendars @ 8.0.1425.11118 (/app/System.Globalization.Calendars.dll)",
		"System.Globalization.Extensions @ 8.0.1425.11118 (/app/System.Globalization.Extensions.dll)",
		"System.IO @ 8.0.1425.11118 (/app/System.IO.dll)",
		"System.IO.Compression @ 8.0.1425.11118 (/app/System.IO.Compression.dll)",
		"System.IO.Compression.Brotli @ 8.0.1425.11118 (/app/System.IO.Compression.Brotli.dll)",
		"System.IO.Compression.FileSystem @ 8.0.1425.11118 (/app/System.IO.Compression.FileSystem.dll)",
		"System.IO.Compression.ZipFile @ 8.0.1425.11118 (/app/System.IO.Compression.ZipFile.dll)",
		"System.IO.FileSystem @ 8.0.1425.11118 (/app/System.IO.FileSystem.dll)",
		"System.IO.FileSystem.AccessControl @ 8.0.1425.11118 (/app/System.IO.FileSystem.AccessControl.dll)",
		"System.IO.FileSystem.DriveInfo @ 8.0.1425.11118 (/app/System.IO.FileSystem.DriveInfo.dll)",
		"System.IO.FileSystem.Primitives @ 8.0.1425.11118 (/app/System.IO.FileSystem.Primitives.dll)",
		"System.IO.FileSystem.Watcher @ 8.0.1425.11118 (/app/System.IO.FileSystem.Watcher.dll)",
		"System.IO.IsolatedStorage @ 8.0.1425.11118 (/app/System.IO.IsolatedStorage.dll)",
		"System.IO.MemoryMappedFiles @ 8.0.1425.11118 (/app/System.IO.MemoryMappedFiles.dll)",
		"System.IO.Pipes @ 8.0.1425.11118 (/app/System.IO.Pipes.dll)",
		"System.IO.Pipes.AccessControl @ 8.0.1425.11118 (/app/System.IO.Pipes.AccessControl.dll)",
		"System.IO.UnmanagedMemoryStream @ 8.0.1425.11118 (/app/System.IO.UnmanagedMemoryStream.dll)",
		"System.Linq @ 8.0.1425.11118 (/app/System.Linq.dll)",
		"System.Linq.Expressions @ 8.0.1425.11118 (/app/System.Linq.Expressions.dll)",
		"System.Linq.Parallel @ 8.0.1425.11118 (/app/System.Linq.Parallel.dll)",
		"System.Linq.Queryable @ 8.0.1425.11118 (/app/System.Linq.Queryable.dll)",
		"System.Memory @ 8.0.1425.11118 (/app/System.Memory.dll)",
		"System.Net @ 8.0.1425.11118 (/app/System.Net.dll)",
		"System.Net.Http @ 8.0.1425.11118 (/app/System.Net.Http.dll)",
		"System.Net.Http.Json @ 8.0.1425.11118 (/app/System.Net.Http.Json.dll)",
		"System.Net.HttpListener @ 8.0.1425.11118 (/app/System.Net.HttpListener.dll)",
		"System.Net.Mail @ 8.0.1425.11118 (/app/System.Net.Mail.dll)",
		"System.Net.NameResolution @ 8.0.1425.11118 (/app/System.Net.NameResolution.dll)",
		"System.Net.NetworkInformation @ 8.0.1425.11118 (/app/System.Net.NetworkInformation.dll)",
		"System.Net.Ping @ 8.0.1425.11118 (/app/System.Net.Ping.dll)",
		"System.Net.Primitives @ 8.0.1425.11118 (/app/System.Net.Primitives.dll)",
		"System.Net.Quic @ 8.0.1425.11118 (/app/System.Net.Quic.dll)",
		"System.Net.Requests @ 8.0.1425.11118 (/app/System.Net.Requests.dll)",
		"System.Net.Security @ 8.0.1425.11118 (/app/System.Net.Security.dll)",
		"System.Net.ServicePoint @ 8.0.1425.11118 (/app/System.Net.ServicePoint.dll)",
		"System.Net.Sockets @ 8.0.1425.11118 (/app/System.Net.Sockets.dll)",
		"System.Net.WebClient @ 8.0.1425.11118 (/app/System.Net.WebClient.dll)",
		"System.Net.WebHeaderCollection @ 8.0.1425.11118 (/app/System.Net.WebHeaderCollection.dll)",
		"System.Net.WebProxy @ 8.0.1425.11118 (/app/System.Net.WebProxy.dll)",
		"System.Net.WebSockets @ 8.0.1425.11118 (/app/System.Net.WebSockets.dll)",
		"System.Net.WebSockets.Client @ 8.0.1425.11118 (/app/System.Net.WebSockets.Client.dll)",
		"System.Numerics @ 8.0.1425.11118 (/app/System.Numerics.dll)",
		"System.Numerics.Vectors @ 8.0.1425.11118 (/app/System.Numerics.Vectors.dll)",
		"System.ObjectModel @ 8.0.1425.11118 (/app/System.ObjectModel.dll)",
		"System.Private.CoreLib @ 8.0.1425.11118 (/app/System.Private.CoreLib.dll)",
		"System.Private.DataContractSerialization @ 8.0.1425.11118 (/app/System.Private.DataContractSerialization.dll)",
		"System.Private.Uri @ 8.0.1425.11118 (/app/System.Private.Uri.dll)",
		"System.Private.Xml @ 8.0.1425.11118 (/app/System.Private.Xml.dll)",
		"System.Private.Xml.Linq @ 8.0.1425.11118 (/app/System.Private.Xml.Linq.dll)",
		"System.Reflection @ 8.0.1425.11118 (/app/System.Reflection.dll)",
		"System.Reflection.DispatchProxy @ 8.0.1425.11118 (/app/System.Reflection.DispatchProxy.dll)",
		"System.Reflection.Emit @ 8.0.1425.11118 (/app/System.Reflection.Emit.dll)",
		"System.Reflection.Emit.ILGeneration @ 8.0.1425.11118 (/app/System.Reflection.Emit.ILGeneration.dll)",
		"System.Reflection.Emit.Lightweight @ 8.0.1425.11118 (/app/System.Reflection.Emit.Lightweight.dll)",
		"System.Reflection.Extensions @ 8.0.1425.11118 (/app/System.Reflection.Extensions.dll)",
		"System.Reflection.Metadata @ 8.0.1425.11118 (/app/System.Reflection.Metadata.dll)",
		"System.Reflection.Primitives @ 8.0.1425.11118 (/app/System.Reflection.Primitives.dll)",
		"System.Reflection.TypeExtensions @ 8.0.1425.11118 (/app/System.Reflection.TypeExtensions.dll)",
		"System.Resources.Reader @ 8.0.1425.11118 (/app/System.Resources.Reader.dll)",
		"System.Resources.ResourceManager @ 8.0.1425.11118 (/app/System.Resources.ResourceManager.dll)",
		"System.Resources.Writer @ 8.0.1425.11118 (/app/System.Resources.Writer.dll)",
		"System.Runtime @ 8.0.1425.11118 (/app/System.Runtime.dll)",
		"System.Runtime.CompilerServices.Unsafe @ 8.0.1425.11118 (/app/System.Runtime.CompilerServices.Unsafe.dll)",
		"System.Runtime.CompilerServices.VisualC @ 8.0.1425.11118 (/app/System.Runtime.CompilerServices.VisualC.dll)",
		"System.Runtime.Extensions @ 8.0.1425.11118 (/app/System.Runtime.Extensions.dll)",
		"System.Runtime.Handles @ 8.0.1425.11118 (/app/System.Runtime.Handles.dll)",
		"System.Runtime.InteropServices @ 8.0.1425.11118 (/app/System.Runtime.InteropServices.dll)",
		"System.Runtime.InteropServices.JavaScript @ 8.0.1425.11118 (/app/System.Runtime.InteropServices.JavaScript.dll)",
		"System.Runtime.InteropServices.RuntimeInformation @ 8.0.1425.11118 (/app/System.Runtime.InteropServices.RuntimeInformation.dll)",
		"System.Runtime.Intrinsics @ 8.0.1425.11118 (/app/System.Runtime.Intrinsics.dll)",
		"System.Runtime.Loader @ 8.0.1425.11118 (/app/System.Runtime.Loader.dll)",
		"System.Runtime.Numerics @ 8.0.1425.11118 (/app/System.Runtime.Numerics.dll)",
		"System.Runtime.Serialization @ 8.0.1425.11118 (/app/System.Runtime.Serialization.dll)",
		"System.Runtime.Serialization.Formatters @ 8.0.1425.11118 (/app/System.Runtime.Serialization.Formatters.dll)",
		"System.Runtime.Serialization.Json @ 8.0.1425.11118 (/app/System.Runtime.Serialization.Json.dll)",
		"System.Runtime.Serialization.Primitives @ 8.0.1425.11118 (/app/System.Runtime.Serialization.Primitives.dll)",
		"System.Runtime.Serialization.Xml @ 8.0.1425.11118 (/app/System.Runtime.Serialization.Xml.dll)",
		"System.Security @ 8.0.1425.11118 (/app/System.Security.dll)",
		"System.Security.AccessControl @ 8.0.1425.11118 (/app/System.Security.AccessControl.dll)",
		"System.Security.Claims @ 8.0.1425.11118 (/app/System.Security.Claims.dll)",
		"System.Security.Cryptography @ 8.0.1425.11118 (/app/System.Security.Cryptography.dll)",
		"System.Security.Cryptography.Algorithms @ 8.0.1425.11118 (/app/System.Security.Cryptography.Algorithms.dll)",
		"System.Security.Cryptography.Cng @ 8.0.1425.11118 (/app/System.Security.Cryptography.Cng.dll)",
		"System.Security.Cryptography.Csp @ 8.0.1425.11118 (/app/System.Security.Cryptography.Csp.dll)",
		"System.Security.Cryptography.Encoding @ 8.0.1425.11118 (/app/System.Security.Cryptography.Encoding.dll)",
		"System.Security.Cryptography.OpenSsl @ 8.0.1425.11118 (/app/System.Security.Cryptography.OpenSsl.dll)",
		"System.Security.Cryptography.Primitives @ 8.0.1425.11118 (/app/System.Security.Cryptography.Primitives.dll)",
		"System.Security.Cryptography.X509Certificates @ 8.0.1425.11118 (/app/System.Security.Cryptography.X509Certificates.dll)",
		"System.Security.Principal @ 8.0.1425.11118 (/app/System.Security.Principal.dll)",
		"System.Security.Principal.Windows @ 8.0.1425.11118 (/app/System.Security.Principal.Windows.dll)",
		"System.Security.SecureString @ 8.0.1425.11118 (/app/System.Security.SecureString.dll)",
		"System.ServiceModel.Web @ 8.0.1425.11118 (/app/System.ServiceModel.Web.dll)",
		"System.ServiceProcess @ 8.0.1425.11118 (/app/System.ServiceProcess.dll)",
		"System.Text.Encoding @ 8.0.1425.11118 (/app/System.Text.Encoding.dll)",
		"System.Text.Encoding.CodePages @ 8.0.1425.11118 (/app/System.Text.Encoding.CodePages.dll)",
		"System.Text.Encoding.Extensions @ 8.0.1425.11118 (/app/System.Text.Encoding.Extensions.dll)",
		"System.Text.Encodings.Web @ 8.0.1425.11118 (/app/System.Text.Encodings.Web.dll)",
		"System.Text.Json @ 8.0.1425.11118 (/app/System.Text.Json.dll)",
		"System.Text.RegularExpressions @ 8.0.1425.11118 (/app/System.Text.RegularExpressions.dll)",
		"System.Threading @ 8.0.1425.11118 (/app/System.Threading.dll)",
		"System.Threading.Channels @ 8.0.1425.11118 (/app/System.Threading.Channels.dll)",
		"System.Threading.Overlapped @ 8.0.1425.11118 (/app/System.Threading.Overlapped.dll)",
		"System.Threading.Tasks @ 8.0.1425.11118 (/app/System.Threading.Tasks.dll)",
		"System.Threading.Tasks.Dataflow @ 8.0.1425.11118 (/app/System.Threading.Tasks.Dataflow.dll)",
		"System.Threading.Tasks.Extensions @ 8.0.1425.11118 (/app/System.Threading.Tasks.Extensions.dll)",
		"System.Threading.Tasks.Parallel @ 8.0.1425.11118 (/app/System.Threading.Tasks.Parallel.dll)",
		"System.Threading.Thread @ 8.0.1425.11118 (/app/System.Threading.Thread.dll)",
		"System.Threading.ThreadPool @ 8.0.1425.11118 (/app/System.Threading.ThreadPool.dll)",
		"System.Threading.Timer @ 8.0.1425.11118 (/app/System.Threading.Timer.dll)",
		"System.Transactions @ 8.0.1425.11118 (/app/System.Transactions.dll)",
		"System.Transactions.Local @ 8.0.1425.11118 (/app/System.Transactions.Local.dll)",
		"System.ValueTuple @ 8.0.1425.11118 (/app/System.ValueTuple.dll)",
		"System.Web @ 8.0.1425.11118 (/app/System.Web.dll)",
		"System.Web.HttpUtility @ 8.0.1425.11118 (/app/System.Web.HttpUtility.dll)",
		"System.Windows @ 8.0.1425.11118 (/app/System.Windows.dll)",
		"System.Xml @ 8.0.1425.11118 (/app/System.Xml.dll)",
		"System.Xml.Linq @ 8.0.1425.11118 (/app/System.Xml.Linq.dll)",
		"System.Xml.ReaderWriter @ 8.0.1425.11118 (/app/System.Xml.ReaderWriter.dll)",
		"System.Xml.Serialization @ 8.0.1425.11118 (/app/System.Xml.Serialization.dll)",
		"System.Xml.XDocument @ 8.0.1425.11118 (/app/System.Xml.XDocument.dll)",
		"System.Xml.XPath @ 8.0.1425.11118 (/app/System.Xml.XPath.dll)",
		"System.Xml.XPath.XDocument @ 8.0.1425.11118 (/app/System.Xml.XPath.XDocument.dll)",
		"System.Xml.XmlDocument @ 8.0.1425.11118 (/app/System.Xml.XmlDocument.dll)",
		"System.Xml.XmlSerializer @ 8.0.1425.11118 (/app/System.Xml.XmlSerializer.dll)",
		"WindowsBase @ 8.0.1425.11118 (/app/WindowsBase.dll)",
		"mscorlib @ 8.0.1425.11118 (/app/mscorlib.dll)",
		"netstandard @ 8.0.1425.11118 (/app/netstandard.dll)",
	)

	assertAllDepEntriesWithoutExecutables := func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		t.Helper()
		for _, p := range pkgs {
			// assert that all packages DO NOT have an executable associated with it
			m, ok := p.Metadata.(pkg.DotnetDepsEntry)
			if !ok {
				t.Fatalf("expected metadata to be of type DotnetDepsEntry")
			}
			if len(m.Executables) != 0 {
				t.Errorf("expected no executables for package %s, found %d", p.Name, len(m.Executables))
			}
		}

		actual := extractMatchingPackage(t, "Newtonsoft.Json", pkgs)
		expected := pkg.Package{
			Name:      "Newtonsoft.Json",
			Version:   "13.0.3",
			Locations: file.NewLocationSet(file.NewLocation("/app/dotnetapp.deps.json")),
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Newtonsoft.Json@13.0.3",
			Metadata: pkg.DotnetDepsEntry{
				Name:        "Newtonsoft.Json",
				Version:     "13.0.3",
				Path:        "newtonsoft.json/13.0.3",
				Sha512:      "sha512-HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ==",
				HashPath:    "newtonsoft.json.13.0.3.nupkg.sha512",
				Executables: nil, // important!
			},
		}

		pkgtest.AssertPackagesEqualIgnoreLayers(t, expected, actual)
	}

	assertAllDepEntriesWithExecutables := func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		t.Helper()
		for _, p := range pkgs {
			// assert that all packages have an executable associated with it
			m, ok := p.Metadata.(pkg.DotnetDepsEntry)
			if !ok {
				t.Fatalf("expected metadata to be of type DotnetDepsEntry")
			}
			if len(m.Executables) != 1 {
				t.Errorf("expected exactly one executable for package %s, found %d", p.Name, len(m.Executables))
			}
		}
	}

	assertAlmostAllDepEntriesWithExecutables := func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		t.Helper()
		for _, p := range pkgs {
			// assert that all packages have an executable associated with it
			m, ok := p.Metadata.(pkg.DotnetDepsEntry)
			if !ok {
				t.Fatalf("expected metadata to be of type DotnetDepsEntry")
			}
			if len(m.Executables) != 1 {
				if m.Name == "Humanizer" {
					// there is only one "virtual" package that doesn't have an actual DLL associated
					assert.Empty(t, m.Executables)
					continue
				}
				t.Errorf("expected exactly one executable for package %s, found %d", p.Name, len(m.Executables))
			}
		}

		actual := extractMatchingPackage(t, "dotnetapp", pkgs)

		expected := pkg.Package{
			Name:    "dotnetapp",
			Version: "1.0.0",
			FoundBy: "",
			Locations: file.NewLocationSet(
				file.NewLocation("/app/dotnetapp.deps.json"),
				file.NewLocation("/app/dotnetapp.dll"),
			),
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/dotnetapp@1.0.0",
			Metadata: pkg.DotnetDepsEntry{
				Name:    "dotnetapp",
				Version: "1.0.0",
				// note: the main package does not have a hash/path/etc
				Executables: map[string]pkg.DotnetPortableExecutableEntry{
					"dotnetapp.dll": {
						AssemblyVersion: "1.0.0.0",
						InternalName:    "dotnetapp.dll",
						CompanyName:     "dotnetapp",
						ProductName:     "dotnetapp",
						ProductVersion:  "1.0.0",
					},
				},
			},
		}

		pkgtest.AssertPackagesEqualIgnoreLayers(t, expected, actual)
	}

	assertAllBinaryEntries := func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		t.Helper()
		for _, p := range pkgs {
			if p.Name == "Microsoft.NETCore.App" {
				// for the runtime app we created ourselves there is no metadata for
				continue
			}
			// assert that all packages have an executable associated with it
			m, ok := p.Metadata.(pkg.DotnetPortableExecutableEntry)
			if !ok {
				t.Fatalf("expected metadata to be of type DotnetPortableExecutableEntry")
			}

			assert.NotNil(t, m, "expected metadata to be a non-nil DotnetPortableExecutableEntry")
		}

		actual := extractMatchingPackage(t, "dotnetapp", pkgs)

		expected := pkg.Package{
			Name:    "dotnetapp",
			Version: "1.0.0.0", // important: in the dep.json this is 1.0.0, now the assembly version is used
			FoundBy: "",
			Locations: file.NewLocationSet(
				// important: we only have the dll as evidence
				file.NewLocation("/app/dotnetapp.dll"),
			),
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/dotnetapp@1.0.0.0", // important: in the dep.json this is 1.0.0, now the assembly version is used
			Metadata: pkg.DotnetPortableExecutableEntry{
				AssemblyVersion: "1.0.0.0",
				InternalName:    "dotnetapp.dll",
				CompanyName:     "dotnetapp",
				ProductName:     "dotnetapp",
				ProductVersion:  "1.0.0",
			},
		}

		pkgtest.AssertPackagesEqualIgnoreLayers(t, expected, actual)

		actual = extractMatchingPackage(t, "Json.NET", pkgs)

		expected = pkg.Package{
			Name:      "Json.NET",     // TODO: could we have done this better? We expected Newtonsoft.Json
			Version:   "13.0.3.27908", // TODO: should we use the product version here?
			Locations: file.NewLocationSet(file.NewLocation("/app/Newtonsoft.Json.dll")),
			Language:  pkg.Dotnet,
			Type:      pkg.DotnetPkg,
			PURL:      "pkg:nuget/Json.NET@13.0.3.27908", // TODO: should we use the product version here?
			Metadata: pkg.DotnetPortableExecutableEntry{
				AssemblyVersion: "13.0.0.0",
				LegalCopyright:  "Copyright © James Newton-King 2008",
				Comments:        "Json.NET is a popular high-performance JSON framework for .NET",
				InternalName:    "Newtonsoft.Json.dll",
				CompanyName:     "Newtonsoft",
				ProductName:     "Json.NET",
				ProductVersion:  "13.0.3+0a2e291c0d9c0c7675d445703e51750363a549ef",
			},
		}

		pkgtest.AssertPackagesEqualIgnoreLayers(t, expected, actual)

	}

	assertSingleFileDeployment := func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		t.Helper()
		for _, p := range pkgs {
			// assert that all packages have an executable associated with it
			m, ok := p.Metadata.(pkg.DotnetPortableExecutableEntry)
			if !ok {
				t.Fatalf("expected metadata to be of type DotnetPortableExecutableEntry")
			}

			assert.NotNil(t, m, "expected metadata to be a non-nil DotnetPortableExecutableEntry")
		}

		actual := extractMatchingPackage(t, "dotnetapp", pkgs)

		expected := pkg.Package{
			Name:    "dotnetapp",
			Version: "1.0.0.0", // important: in the dep.json this is 1.0.0, now the assembly version is used
			FoundBy: "",
			Locations: file.NewLocationSet(
				// important: we only have the exe as evidence
				file.NewLocation("/app/dotnetapp.exe"),
			),
			Language: pkg.Dotnet,
			Type:     pkg.DotnetPkg,
			PURL:     "pkg:nuget/dotnetapp@1.0.0.0", // important: in the dep.json this is 1.0.0, now the assembly version is used
			Metadata: pkg.DotnetPortableExecutableEntry{
				AssemblyVersion: "1.0.0.0",
				InternalName:    "dotnetapp.dll",
				CompanyName:     "dotnetapp",
				ProductName:     "dotnetapp",
				ProductVersion:  "1.0.0",
			},
		}
		pkgtest.AssertPackagesEqualIgnoreLayers(t, expected, actual)
	}

	assertAccurateNetRuntimePackage := func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		// the package with the CPE is the runtime package
		for _, p := range pkgs {
			if len(p.CPEs) == 0 {
				continue
			}
			assert.Contains(t, p.Name, "Microsoft.NETCore.App")
			return
		}
		t.Error("expected at least one runtime package with a CPE")
	}

	cases := []struct {
		name         string
		fixture      string
		expectedPkgs []string
		expectedRels []string
		assertion    func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship)
		cataloger    pkg.Cataloger
	}{
		{
			name:         "deps cataloger",
			fixture:      "image-net8-app",
			cataloger:    NewDotnetDepsCataloger(),
			expectedPkgs: net8AppExpectedDepPkgs,
			expectedRels: net8AppExpectedDepRelationships,
			assertion:    assertAllDepEntriesWithoutExecutables,
		},
		{
			name:         "combined cataloger",
			fixture:      "image-net8-app",
			cataloger:    NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: net8AppExpectedDepPkgs,
			expectedRels: net8AppDepOnlyRelationships,
			assertion:    assertAlmostAllDepEntriesWithExecutables, // important! this is what makes this case different from the previous one... dep entries have attached executables
		},
		{
			name:         "combined cataloger (with runtime)",
			fixture:      "image-net8-app-with-runtime",
			cataloger:    NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: net8AppExpectedDepPkgsWithRuntime,
			expectedRels: net8AppDepOnlyRelationshipsWithRuntime,
			assertion:    assertAccurateNetRuntimePackage,
		},
		{
			name:      "combined cataloger (with runtime, no deps.json anywhere)",
			fixture:   "image-net8-app-with-runtime-nodepsjson",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: func() []string {
				// all the same packages we found in "image-net8-app-with-runtime", however we create a runtime package out of all of the DLLs we found instead
				x := net8AppBinaryOnlyPkgs
				x = append(x, "Microsoft.NETCore.App @ 8.0.14 (/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.14/Microsoft.CSharp.dll)")
				return x
			}(),
			// important: no relationships should be found
			assertion: func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
				assertAllBinaryEntries(t, pkgs, relationships)
				assertAccurateNetRuntimePackage(t, pkgs, relationships)
			},
		},
		{
			name:         "combined cataloger (require dll pairings)",
			fixture:      "image-net8-app",
			cataloger:    NewDotnetDepsBinaryCataloger(CatalogerConfig{DepPackagesMustHaveDLL: true}),
			expectedPkgs: net8AppExpectedDepPkgsWithoutUnpairedDlls,
			expectedRels: []string{
				// the odd thing (but expected) is that the Humanizer.Core entries have a dependency to each Humanizer.Core.* locale entry
				// because we're skipping over the "virtual" Humanizer package which does not have any associated DLLs with it.
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.af @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ar @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.az @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.bg @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.bn-BD @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.cs @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.da @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.de @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.el @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.es @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fa @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fi-FI @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fr @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.fr-BE @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.he @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.hr @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.hu @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.hy @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.id @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.is @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.it @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ja @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ko-KR @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ku @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.lv @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ms-MY @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.mt @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.nb @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.nb-NO @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.nl @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.pl @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.pt @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ro @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.ru @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sk @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sl @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sr @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sr-Latn @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.sv @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.th-TH @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.tr @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.uk @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.uz-Cyrl-UZ @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.uz-Latn-UZ @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.vi @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.zh-CN @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.zh-Hans @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] Humanizer.Core.zh-Hant @ 2.14.1 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.af @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.ar @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.az @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.bg @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.bn-BD @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.cs @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.da @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.de @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.el @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.es @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.fa @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.fi-FI @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.fr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.fr-BE @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.he @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.hr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.hu @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.hy @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.id @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.is @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.it @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.ja @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.ko-KR @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.ku @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.lv @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.ms-MY @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.mt @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.nb @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.nb-NO @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.nl @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.pl @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.pt @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.ro @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.ru @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.sk @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.sl @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.sr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.sr-Latn @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.sv @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.th-TH @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.tr @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.uk @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.uz-Cyrl-UZ @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.uz-Latn-UZ @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.vi @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.zh-CN @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.zh-Hans @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Humanizer.Core.zh-Hant @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				"Newtonsoft.Json @ 13.0.3 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
			},
			assertion: assertAllDepEntriesWithExecutables, // important! we want the Humanizer package without a DLL to be ignored
		},
		{
			name:         "PE cataloger",
			fixture:      "image-net8-app",
			cataloger:    NewDotnetPortableExecutableCataloger(),
			expectedPkgs: net8AppBinaryOnlyPkgs,
			// important: no relationships should be found
			assertion: assertAllBinaryEntries,
		},
		{
			name:      "deps cataloger (no deps.json)",
			fixture:   "image-net8-app-no-depjson",
			cataloger: NewDotnetDepsCataloger(),
			// there should be no packages found!
		},
		{
			name:         "combined cataloger (no deps.json)",
			fixture:      "image-net8-app-no-depjson",
			cataloger:    NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: net8AppBinaryOnlyPkgs,
			// important: no relationships should be found
			assertion: assertAllBinaryEntries,
		},
		{
			name:         "pe cataloger (no deps.json)",
			fixture:      "image-net8-app-no-depjson",
			cataloger:    NewDotnetPortableExecutableCataloger(),
			expectedPkgs: net8AppBinaryOnlyPkgs,
			// important: no relationships should be found
			assertion: assertAllBinaryEntries,
		},
		{
			name:      "deps cataloger (single file)",
			fixture:   "image-net8-app-single-file",
			cataloger: NewDotnetDepsCataloger(),
			// there should be no packages found!
		},
		{
			name:      "combined cataloger (single file)",
			fixture:   "image-net8-app-single-file",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),

			// important: no relationships should be found
			expectedPkgs: []string{
				"dotnetapp @ 1.0.0.0 (/app/dotnetapp.exe)",
			},
			assertion: assertSingleFileDeployment,
		},
		{
			name:      "pe cataloger (single file)",
			fixture:   "image-net8-app-single-file",
			cataloger: NewDotnetPortableExecutableCataloger(),
			// important: no relationships should be found
			expectedPkgs: []string{
				"dotnetapp @ 1.0.0.0 (/app/dotnetapp.exe)",
			},
			assertion: assertSingleFileDeployment,
		},
		{
			name:         "deps cataloger (self-contained)",
			fixture:      "image-net8-app-self-contained",
			cataloger:    NewDotnetDepsCataloger(),
			expectedPkgs: net8AppExpectedDepsSelfContainedPkgs,
			expectedRels: net8AppExpectedDepSelfContainedRelationships,
		},
		{
			name:      "combined cataloger (self-contained)",
			fixture:   "image-net8-app-self-contained",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			// we care about DLL claims in the deps.json, so the main application inherits all relationships to/from humarizer
			expectedPkgs: net8AppExpectedDepSelfContainedPkgs,
			expectedRels: net8AppExpectedDepSelfContainedRelationships,
			assertion:    assertAccurateNetRuntimePackage,
		},
		{
			name:      "pe cataloger (self-contained)",
			fixture:   "image-net8-app-self-contained",
			cataloger: NewDotnetPortableExecutableCataloger(),
			// important: no relationships should be found
			expectedPkgs: net8AppExpectedBinarySelfContainedPkgs,
		},
		{
			name:      "combined cataloger (private assets + require dlls)",
			fixture:   "image-net8-privateassets",
			cataloger: NewDotnetDepsBinaryCataloger(CatalogerConfig{DepPackagesMustHaveDLL: true}),
			expectedPkgs: []string{
				"dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
			},
		},
		{
			name:      "combined cataloger (private assets)",
			fixture:   "image-net8-privateassets",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: []string{
				"dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
			},
		},
		{
			name:      "combined cataloger (ilrepack + require dlls)",
			fixture:   "image-net8-ilrepack",
			cataloger: NewDotnetDepsBinaryCataloger(CatalogerConfig{DepPackagesMustHaveDLL: true}),
			expectedPkgs: []string{
				"dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
			},
		},
		{
			// TODO: this is to help us out in the future... we can use TypeDef info from the Metadata table to determine
			// if package names are any "namespace" values of the assembly. Today we don't do this so we relax claims
			// when bundling is detected instead of attempting to check for namespace values in TypeDef entries
			// and correlate against deps.json entries (which is not a sure thing!).
			name:      "combined cataloger (ilrepack)",
			fixture:   "image-net8-ilrepack",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: func() []string {
				x := net8AppExpectedDepPkgs
				x = append(x,
					"ILRepack @ 2.0.33 (/app/dotnetapp.deps.json)",
					"ILRepack.FullAuto @ 1.6.0 (/app/dotnetapp.deps.json)",
				)
				return x
			}(),
			expectedRels: func() []string {
				x := net8AppExpectedDepRelationships
				x = append(x,
					"ILRepack @ 2.0.33 (/app/dotnetapp.deps.json) [dependency-of] ILRepack.FullAuto @ 1.6.0 (/app/dotnetapp.deps.json)",
					"ILRepack.FullAuto @ 1.6.0 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
				)
				return x
			}(),
		},
		{
			name:      "net2 app, combined cataloger (private assets)",
			fixture:   "image-net2-app",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: []string{
				"Microsoft.NETCore.App @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json)",
				"Microsoft.NETCore.DotNetHostPolicy @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json)",
				"Serilog @ 2.10.0 (/app/helloworld.deps.json)",
				"Serilog.Sinks.Console @ 4.0.1 (/app/helloworld.deps.json)",
				"helloworld @ 1.0.0 (/app/helloworld.deps.json)",
				"runtime.linux-x64.Microsoft.NETCore.App @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json)",
				"runtime.linux-x64.Microsoft.NETCore.DotNetHostPolicy @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json)", // a compile target reference
			},
			expectedRels: []string{
				"Microsoft.NETCore.DotNetHostPolicy @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json) [dependency-of] Microsoft.NETCore.App @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json)",
				"Serilog @ 2.10.0 (/app/helloworld.deps.json) [dependency-of] Serilog.Sinks.Console @ 4.0.1 (/app/helloworld.deps.json)",
				"Serilog @ 2.10.0 (/app/helloworld.deps.json) [dependency-of] helloworld @ 1.0.0 (/app/helloworld.deps.json)",
				"Serilog.Sinks.Console @ 4.0.1 (/app/helloworld.deps.json) [dependency-of] helloworld @ 1.0.0 (/app/helloworld.deps.json)",
				"runtime.linux-x64.Microsoft.NETCore.App @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json) [dependency-of] Microsoft.NETCore.App @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json)",
				"runtime.linux-x64.Microsoft.NETCore.App @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json) [dependency-of] helloworld @ 1.0.0 (/app/helloworld.deps.json)",
				"runtime.linux-x64.Microsoft.NETCore.DotNetHostPolicy @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json) [dependency-of] Microsoft.NETCore.DotNetHostPolicy @ 2.2.8 (/usr/share/dotnet/shared/Microsoft.NETCore.App/2.2.8/Microsoft.NETCore.App.deps.json)",
			},
			assertion: assertAccurateNetRuntimePackage,
		},
		{
			name:      "libman support",
			fixture:   "image-net6-asp-libman",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			expectedPkgs: []string{
				"LibManSample @ 1.0.0 (/app/LibManSample.deps.json)",
				"jquery @ 3.3.1 (/app/libman.json)",
			},
			expectedRels: []string{
				"jquery @ 3.3.1 (/app/libman.json) [dependency-of] LibManSample @ 1.0.0 (/app/LibManSample.deps.json)",
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.assertion == nil {
				tt.assertion = func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {}
			}
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.fixture).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				ExpectsPackageStrings(tt.expectedPkgs).
				ExpectsRelationshipStrings(tt.expectedRels).
				ExpectsAssertion(tt.assertion).
				TestCataloger(t, tt.cataloger)
		})
	}
}

func TestDotnetDepsCataloger_regressions(t *testing.T) {

	assertPackages := func(mustHave []string, mustNotHave []string) func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
		expected := strset.New(mustHave...)
		notExpected := strset.New(mustNotHave...)
		return func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {

			for _, p := range pkgs {
				expected.Remove(p.Name)
				if notExpected.Has(p.Name) {
					t.Errorf("unexpected package: %s", p.Name)
				}
			}
			if expected.IsEmpty() {
				return
			}
			t.Errorf("missing packages: %s", expected.List())
		}
	}

	cases := []struct {
		name      string
		fixture   string
		assertion func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship)
		cataloger pkg.Cataloger
	}{
		{
			// during development, these version resources tended to be corrupted
			name:      "Newtonsoft dll details",
			fixture:   "image-net8-app-no-depjson",
			cataloger: NewDotnetPortableExecutableCataloger(),
			assertion: func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
				// TODO: name should be "Newtonsoft.Json" (bad metadata in the artifact)
				actual := extractMatchingPackage(t, "Json.NET", pkgs)

				expected := pkg.Package{
					Name:      "Json.NET",
					Version:   "13.0.3.27908", // TODO should we parse the product version to get 13.0.3?
					Locations: file.NewLocationSet(file.NewLocation("/app/Newtonsoft.Json.dll")),
					Language:  pkg.Dotnet,
					Type:      pkg.DotnetPkg,
					PURL:      "pkg:nuget/Json.NET@13.0.3.27908",
					Metadata: pkg.DotnetPortableExecutableEntry{
						AssemblyVersion: "13.0.0.0",
						LegalCopyright:  "Copyright © James Newton-King 2008",
						Comments:        "Json.NET is a popular high-performance JSON framework for .NET",
						InternalName:    "Newtonsoft.Json.dll",
						CompanyName:     "Newtonsoft",
						ProductName:     "Json.NET",
						ProductVersion:  "13.0.3+0a2e291c0d9c0c7675d445703e51750363a549ef",
					},
				}

				pkgtest.AssertPackagesEqualIgnoreLayers(t, expected, actual)
			},
		},
		{
			name:      "indirect packages references",
			fixture:   "image-net8-compile-target",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			assertion: assertPackages(
				[]string{
					"DotNetNuke.Core", // uses a compile target reference in the deps.json
					"Umbraco.Cms",     // this is the parent of other packages which do have DLLs included (even though it does not have any DLLs)
				},
				[]string{
					"StyleCop.Analyzers",     // this is a development tool
					"Microsoft.NET.Test.Sdk", // this is a development tool
					"jQuery",                 // has no DLLs but has javascript assets
				},
			),
		},
		{
			name:      "not propagating claims",
			fixture:   "image-net8-compile-target",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig().WithPropagateDLLClaimsToParents(false)),
			assertion: assertPackages(
				[]string{
					"DotNetNuke.Core", // uses a compile target reference in the deps.json

				},
				[]string{
					"Umbraco.Cms",            // this is the parent of other packages which do have DLLs included (even though it does not have any DLLs)
					"StyleCop.Analyzers",     // this is a development tool
					"Microsoft.NET.Test.Sdk", // this is a development tool under the debug configuration (we build the release configuration)
					"jQuery",                 // has no DLLs but has javascript assets -- this is bad behavior (as we want to detect this)
				},
			),
		},
		{
			name:    "not requiring claims finds jquery",
			fixture: "image-net8-compile-target",
			cataloger: NewDotnetDepsBinaryCataloger(CatalogerConfig{
				DepPackagesMustHaveDLL:             false,
				DepPackagesMustClaimDLL:            false,
				PropagateDLLClaimsToParents:        false,
				RelaxDLLClaimsWhenBundlingDetected: false,
			}),
			assertion: assertPackages(
				[]string{
					"jQuery",             // has no DLLs but has javascript assets
					"StyleCop.Analyzers", // this is a development tool -- this is bad behavior (since we should not detect this), but cannot be helped
				},
				[]string{
					"Microsoft.NET.Test.Sdk", // this is a development tool under the debug configuration (we build the release configuration)
				},
			),
		},
		{
			name:      "libman support",
			fixture:   "image-net6-asp-libman",
			cataloger: NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()),
			assertion: assertPackages(
				[]string{
					"jquery", // a javascript package, not the nuget package
				},
				[]string{
					"vendor", // this is the string reference for a filesystem provider
					"lodash", // this is from a filesystem provider, which is not supported
				},
			),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.assertion == nil {
				t.Fatalf("assertion is required")
			}
			pkgtest.NewCatalogTester().
				WithImageResolver(t, tt.fixture).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				ExpectsAssertion(tt.assertion).
				TestCataloger(t, tt.cataloger)
		})
	}
}

func Test_corruptDotnetPE(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/glob-paths/src").
		Expects(nil, nil). // we shouldn't find packages nor error out
		TestCataloger(t, NewDotnetPortableExecutableCataloger())
}

func Test_corruptDotnetDeps(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/glob-paths/src").
		Expects(nil, nil). // we shouldn't find packages nor error out
		TestCataloger(t, NewDotnetDepsCataloger())
}

func TestParseDotnetDeps(t *testing.T) {
	fixture := "test-fixtures/dir-example-1"
	fixtureLocationSet := file.NewLocationSet(file.NewLocation("TestLibrary.deps.json"))
	rootPkg := pkg.Package{
		Name:      "TestLibrary",
		Version:   "1.0.0",
		PURL:      "pkg:nuget/TestLibrary@1.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:    "TestLibrary",
			Version: "1.0.0",
		},
	}
	testCommon := pkg.Package{
		Name:      "TestCommon",
		Version:   "1.0.0",
		PURL:      "pkg:nuget/TestCommon@1.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:    "TestCommon",
			Version: "1.0.0",
		},
	}
	awssdkcore := pkg.Package{
		Name:      "AWSSDK.Core",
		Version:   "3.7.10.6",
		PURL:      "pkg:nuget/AWSSDK.Core@3.7.10.6",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "AWSSDK.Core",
			Version:  "3.7.10.6",
			Sha512:   "sha512-kHBB+QmosVaG6DpngXQ8OlLVVNMzltNITfsRr68Z90qO7dSqJ2EHNd8dtBU1u3AQQLqqFHOY0lfmbpexeH6Pew==",
			Path:     "awssdk.core/3.7.10.6",
			HashPath: "awssdk.core.3.7.10.6.nupkg.sha512",
		},
	}
	msftDependencyInjectionAbstractions := pkg.Package{
		Name:      "Microsoft.Extensions.DependencyInjection.Abstractions",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.DependencyInjection.Abstractions@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.DependencyInjection.Abstractions",
			Version:  "6.0.0",
			Sha512:   "sha512-xlzi2IYREJH3/m6+lUrQlujzX8wDitm4QGnUu6kUXTQAWPuZY8i+ticFJbzfqaetLA6KR/rO6Ew/HuYD+bxifg==",
			Path:     "microsoft.extensions.dependencyinjection.abstractions/6.0.0",
			HashPath: "microsoft.extensions.dependencyinjection.abstractions.6.0.0.nupkg.sha512",
		},
	}
	msftDependencyInjection := pkg.Package{
		Name:      "Microsoft.Extensions.DependencyInjection",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.DependencyInjection@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.DependencyInjection",
			Version:  "6.0.0",
			Sha512:   "sha512-k6PWQMuoBDGGHOQTtyois2u4AwyVcIwL2LaSLlTZQm2CYcJ1pxbt6jfAnpWmzENA/wfrYRI/X9DTLoUkE4AsLw==",
			Path:     "microsoft.extensions.dependencyinjection/6.0.0",
			HashPath: "microsoft.extensions.dependencyinjection.6.0.0.nupkg.sha512",
		},
	}
	msftLoggingAbstractions := pkg.Package{
		Name:      "Microsoft.Extensions.Logging.Abstractions",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Logging.Abstractions@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Logging.Abstractions",
			Version:  "6.0.0",
			Sha512:   "sha512-/HggWBbTwy8TgebGSX5DBZ24ndhzi93sHUBDvP1IxbZD7FDokYzdAr6+vbWGjw2XAfR2EJ1sfKUotpjHnFWPxA==",
			Path:     "microsoft.extensions.logging.abstractions/6.0.0",
			HashPath: "microsoft.extensions.logging.abstractions.6.0.0.nupkg.sha512",
		},
	}
	msftExtensionsLogging := pkg.Package{
		Name:      "Microsoft.Extensions.Logging",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Logging@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Logging",
			Version:  "6.0.0",
			Sha512:   "sha512-eIbyj40QDg1NDz0HBW0S5f3wrLVnKWnDJ/JtZ+yJDFnDj90VoPuoPmFkeaXrtu+0cKm5GRAwoDf+dBWXK0TUdg==",
			Path:     "microsoft.extensions.logging/6.0.0",
			HashPath: "microsoft.extensions.logging.6.0.0.nupkg.sha512",
		},
	}
	msftExtensionsOptions := pkg.Package{
		Name:      "Microsoft.Extensions.Options",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Options@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Options",
			Version:  "6.0.0",
			Sha512:   "sha512-dzXN0+V1AyjOe2xcJ86Qbo233KHuLEY0njf/P2Kw8SfJU+d45HNS2ctJdnEnrWbM9Ye2eFgaC5Mj9otRMU6IsQ==",
			Path:     "microsoft.extensions.options/6.0.0",
			HashPath: "microsoft.extensions.options.6.0.0.nupkg.sha512",
		},
	}
	msftExtensionsPrimitives := pkg.Package{
		Name:      "Microsoft.Extensions.Primitives",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/Microsoft.Extensions.Primitives@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Microsoft.Extensions.Primitives",
			Version:  "6.0.0",
			Sha512:   "sha512-9+PnzmQFfEFNR9J2aDTfJGGupShHjOuGw4VUv+JB044biSHrnmCIMD+mJHmb2H7YryrfBEXDurxQ47gJZdCKNQ==",
			Path:     "microsoft.extensions.primitives/6.0.0",
			HashPath: "microsoft.extensions.primitives.6.0.0.nupkg.sha512",
		},
	}
	newtonsoftJson := pkg.Package{
		Name:      "Newtonsoft.Json",
		Version:   "13.0.1",
		PURL:      "pkg:nuget/Newtonsoft.Json@13.0.1",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Newtonsoft.Json",
			Version:  "13.0.1",
			Sha512:   "sha512-ppPFpBcvxdsfUonNcvITKqLl3bqxWbDCZIzDWHzjpdAHRFfZe0Dw9HmA0+za13IdyrgJwpkDTDA9fHaxOrt20A==",
			Path:     "newtonsoft.json/13.0.1",
			HashPath: "newtonsoft.json.13.0.1.nupkg.sha512",
		},
	}
	serilogSinksConsole := pkg.Package{
		Name:      "Serilog.Sinks.Console",
		Version:   "4.0.1",
		PURL:      "pkg:nuget/Serilog.Sinks.Console@4.0.1",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Serilog.Sinks.Console",
			Version:  "4.0.1",
			Sha512:   "sha512-apLOvSJQLlIbKlbx+Y2UDHSP05kJsV7mou+fvJoRGs/iR+jC22r8cuFVMjjfVxz/AD4B2UCltFhE1naRLXwKNw==",
			Path:     "serilog.sinks.console/4.0.1",
			HashPath: "serilog.sinks.console.4.0.1.nupkg.sha512",
		},
	}
	serilog := pkg.Package{
		Name:      "Serilog",
		Version:   "2.10.0",
		PURL:      "pkg:nuget/Serilog@2.10.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "Serilog",
			Version:  "2.10.0",
			Sha512:   "sha512-+QX0hmf37a0/OZLxM3wL7V6/ADvC1XihXN4Kq/p6d8lCPfgkRdiuhbWlMaFjR9Av0dy5F0+MBeDmDdRZN/YwQA==",
			Path:     "serilog/2.10.0",
			HashPath: "serilog.2.10.0.nupkg.sha512",
		},
	}
	systemDiagnosticsDiagnosticsource := pkg.Package{
		Name:      "System.Diagnostics.DiagnosticSource",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/System.Diagnostics.DiagnosticSource@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "System.Diagnostics.DiagnosticSource",
			Version:  "6.0.0",
			Sha512:   "sha512-frQDfv0rl209cKm1lnwTgFPzNigy2EKk1BS3uAvHvlBVKe5cymGyHO+Sj+NLv5VF/AhHsqPIUUwya5oV4CHMUw==",
			Path:     "system.diagnostics.diagnosticsource/6.0.0",
			HashPath: "system.diagnostics.diagnosticsource.6.0.0.nupkg.sha512",
		},
	}
	systemRuntimeCompilerServicesUnsafe := pkg.Package{
		Name:      "System.Runtime.CompilerServices.Unsafe",
		Version:   "6.0.0",
		PURL:      "pkg:nuget/System.Runtime.CompilerServices.Unsafe@6.0.0",
		Locations: fixtureLocationSet,
		Language:  pkg.Dotnet,
		Type:      pkg.DotnetPkg,
		Metadata: pkg.DotnetDepsEntry{
			Name:     "System.Runtime.CompilerServices.Unsafe",
			Version:  "6.0.0",
			Sha512:   "sha512-/iUeP3tq1S0XdNNoMz5C9twLSrM/TH+qElHkXWaPvuNOt+99G75NrV0OS2EqHx5wMN7popYjpc8oTjC1y16DLg==",
			Path:     "system.runtime.compilerservices.unsafe/6.0.0",
			HashPath: "system.runtime.compilerservices.unsafe.6.0.0.nupkg.sha512",
		}}

	expectedPkgs := []pkg.Package{
		awssdkcore,
		msftDependencyInjection,
		msftDependencyInjectionAbstractions,
		msftExtensionsLogging,
		msftLoggingAbstractions,
		msftExtensionsOptions,
		msftExtensionsPrimitives,
		newtonsoftJson,
		serilog,
		serilogSinksConsole,
		systemDiagnosticsDiagnosticsource,
		systemRuntimeCompilerServicesUnsafe,
		testCommon,
		rootPkg,
	}

	// ┌── (✓ = is represented in the test)
	// ↓
	//
	// ✓ TestLibrary/1.0.0 (project)
	// ✓  ├── [a] Microsoft.Extensions.DependencyInjection/6.0.0                     [file version: 6.0.21.52210]
	// ✓  │    ├── [b] Microsoft.Extensions.DependencyInjection.Abstractions/6.0.0   [file version: 6.0.21.52210]
	// ✓  │    └── [c!] System.Runtime.CompilerServices.Unsafe/6.0.0                 [NO TARGET INFO]
	// ✓  ├── Microsoft.Extensions.Logging/6.0.0                                     [file version: 6.0.21.52210]
	// ✓  │    ├── Microsoft.Extensions.DependencyInjection/6.0.0                    ...to [a]
	// ✓  │    ├── Microsoft.Extensions.DependencyInjection.Abstractions/6.0.0       ...to [b]
	// ✓  │    ├── Microsoft.Extensions.Logging.Abstractions/6.0.0                   [file version: 6.0.21.52210]
	// ✓  │    ├── Microsoft.Extensions.Options/6.0.0                                [file version: 6.0.21.52210]
	// ✓  │    │    ├── Microsoft.Extensions.DependencyInjection.Abstractions/6.0.0  ...to [b]
	// ✓  │    │    └── Microsoft.Extensions.Primitives/6.0.0                        [file version: 6.0.21.52210]
	// ✓  │    │         └── System.Runtime.CompilerServices.Unsafe/6.0.0            ...to [c!]
	// ✓  │    └── System.Diagnostics.DiagnosticSource/6.0.0                         [NO RUNTIME INFO]
	// ✓  │         └── System.Runtime.CompilerServices.Unsafe/6.0.0                 ...to [c!]
	// ✓  ├── Newtonsoft.Json/13.0.1                                                 [file version: 13.0.1.25517]
	// ✓  ├── [d] Serilog/2.10.0                                                     [file version: 2.10.0.0]
	// ✓  ├── Serilog.Sinks.Console/4.0.1                                            [file version: 4.0.1.0]
	// ✓  │    └── Serilog/2.10.0                                                    ...to [d]
	// ✓  └── [e!] TestCommon/1.0.0                                                  [NOT SERVICEABLE / NO SHA]
	// ✓       └── AWSSDK.Core/3.7.10.6                                              [file version: 3.7.10.6]

	expectedRelationships := []artifact.Relationship{
		{
			From: awssdkcore,
			To:   testCommon,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjection,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjection,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjectionAbstractions,
			To:   msftDependencyInjection,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjectionAbstractions,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftDependencyInjectionAbstractions,
			To:   msftExtensionsOptions,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftExtensionsLogging,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftLoggingAbstractions,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftExtensionsOptions,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: msftExtensionsPrimitives,
			To:   msftExtensionsOptions,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: newtonsoftJson,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serilog,
			To:   serilogSinksConsole,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serilog,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: serilogSinksConsole,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemDiagnosticsDiagnosticsource,
			To:   msftExtensionsLogging,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemRuntimeCompilerServicesUnsafe,
			To:   msftDependencyInjection,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemRuntimeCompilerServicesUnsafe,
			To:   msftExtensionsPrimitives,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: systemRuntimeCompilerServicesUnsafe,
			To:   systemDiagnosticsDiagnosticsource,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: testCommon,
			To:   rootPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestCataloger(t, fixture, NewDotnetDepsCataloger(), expectedPkgs, expectedRelationships)
}

func extractMatchingPackage(t *testing.T, name string, pkgs []pkg.Package) pkg.Package {
	t.Helper()
	for _, p := range pkgs {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("expected to find package %s", name)
	return pkg.Package{}
}
