package dotnet

import (
	"testing"

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
			cataloger: NewDotnetDepsBinaryCataloger(),
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
	net8AppDepOnlyPkgs := []string{
		"Humanizer @ 2.14.1 (/app/dotnetapp.deps.json)",
	}
	net8AppPairedPkgs := []string{
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

	var net8AppExpectedDepPkgs []string
	net8AppExpectedDepPkgs = append(net8AppExpectedDepPkgs, net8AppDepOnlyPkgs...)
	net8AppExpectedDepPkgs = append(net8AppExpectedDepPkgs, net8AppPairedPkgs...)

	net8AppBinaryOnlyPkgs := []string{
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/Humanizer.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/af/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/ar/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/az/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/bg/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/bn-BD/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/cs/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/da/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/de/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/el/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/es/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/fa/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/fi-FI/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/fr-BE/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/fr/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/he/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/hr/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/hu/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/hy/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/id/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/is/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/it/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/ja/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/ku/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/lv/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/nb-NO/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/nb/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/nl/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/pl/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/pt/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/ro/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/ru/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/sk/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/sl/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/sr-Latn/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/sr/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/sv/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/tr/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/uk/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/uz-Cyrl-UZ/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/uz-Latn-UZ/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/vi/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/zh-CN/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/zh-Hans/Humanizer.resources.dll)",
		"Humanizer (net6.0) @ 2.14.1.48190 (/app/zh-Hant/Humanizer.resources.dll)",
		"Humanizer (netstandard2.0) @ 2.14.1.48190 (/app/ko-KR/Humanizer.resources.dll)",
		"Humanizer (netstandard2.0) @ 2.14.1.48190 (/app/ms-MY/Humanizer.resources.dll)",
		"Humanizer (netstandard2.0) @ 2.14.1.48190 (/app/mt/Humanizer.resources.dll)",
		"Humanizer (netstandard2.0) @ 2.14.1.48190 (/app/th-TH/Humanizer.resources.dll)",
		"Json.NET @ 13.0.3.27908 (/app/Newtonsoft.Json.dll)",
		"dotnetapp @ 1.0.0.0 (/app/dotnetapp.dll)",
	}

	net8AppDepOnlyRelationships := []string{
		"Humanizer @ 2.14.1 (/app/dotnetapp.deps.json) [dependency-of] dotnetapp @ 1.0.0 (/app/dotnetapp.deps.json)",
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
	}

	net8AppPairedRelationships := []string{
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

	var net8AppExpectedDepRelationships []string
	net8AppExpectedDepRelationships = append(net8AppExpectedDepRelationships, net8AppDepOnlyRelationships...)
	net8AppExpectedDepRelationships = append(net8AppExpectedDepRelationships, net8AppPairedRelationships...)

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

	cases := []struct {
		name         string
		fixture      string
		expectedPkgs []string
		expectedRels []string
		assertion    func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship)
		cataloger    pkg.Cataloger
	}{
		{
			name:         "net8-app deps cataloger",
			fixture:      "image-net8-app",
			cataloger:    NewDotnetDepsCataloger(),
			expectedPkgs: net8AppExpectedDepPkgs,
			expectedRels: net8AppExpectedDepRelationships,
			assertion:    assertAllDepEntriesWithoutExecutables,
		},
		{
			name:         "net8-app combined cataloger",
			fixture:      "image-net8-app",
			cataloger:    NewDotnetDepsBinaryCataloger(),
			expectedPkgs: net8AppExpectedDepPkgs,
			expectedRels: net8AppExpectedDepRelationships,
			assertion:    assertAllDepEntriesWithExecutables, // important! this is what makes this case different from the previous one... dep entries have attached executables
		},
		{
			name:         "net8-app PE cataloger",
			fixture:      "image-net8-app",
			cataloger:    NewDotnetPortableExecutableCataloger(),
			expectedPkgs: net8AppBinaryOnlyPkgs,
			// important: no relationships should be found
			assertion: assertAllBinaryEntries,
		},
		{
			name:      "net8-app deps cataloger (no deps.json)",
			fixture:   "image-net8-app-no-depjson",
			cataloger: NewDotnetDepsCataloger(),
			// there should be no packages found!
		},
		{
			name:         "net8-app combined cataloger (no deps.json)",
			fixture:      "image-net8-app-no-depjson",
			cataloger:    NewDotnetDepsBinaryCataloger(),
			expectedPkgs: net8AppBinaryOnlyPkgs,
			// important: no relationships should be found
			assertion: assertAllBinaryEntries,
		},
		{
			name:         "net8-app pe cataloger (no deps.json)",
			fixture:      "image-net8-app-no-depjson",
			cataloger:    NewDotnetPortableExecutableCataloger(),
			expectedPkgs: net8AppBinaryOnlyPkgs,
			// important: no relationships should be found
			assertion: assertAllBinaryEntries,
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

func TestDotnetDepsCataloger_problemCases(t *testing.T) {
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

func Test_extractVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "1, 0, 0, 0",
			expected: "1, 0, 0, 0",
		},
		{
			input:    "Release 73",
			expected: "Release 73",
		},
		{
			input:    "4.7.4076.0 built by: NET472REL1LAST_B",
			expected: "4.7.4076.0",
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got := extractVersionFromResourcesValue(test.input)
			assert.Equal(t, test.expected, got)
		})
	}
}

func Test_spaceNormalize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			expected: "some spaces apart",
			input:    " some 	spaces\n\t\t \n\rapart\n",
		},
		{
			expected: "söme ¡nvalid characters",
			input:    "\rsöme \u0001¡nvalid\t characters\n",
		},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			got := spaceNormalize(test.input)
			assert.Equal(t, test.expected, got)
		})
	}
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
	for _, p := range pkgs {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("expected to find package %s", name)
	return pkg.Package{}
}
