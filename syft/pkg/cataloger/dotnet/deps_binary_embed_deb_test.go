package dotnet

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_EmbeddedDepsExtraction(t *testing.T) {
	expectedPkgs := []string{
		"Newtonsoft.Json @ 13.0.3 (dotnet-single-file-embed-deps-json.exe)",
		"app @ 1.0.0 (dotnet-single-file-embed-deps-json.exe)",
		"dotnet-single-file-embed-deps-json @  (dotnet-single-file-embed-deps-json.exe)", // from PE binary metadata
		"runtimepack.Microsoft.NETCore.App.Runtime.linux-x64 @ 8.0.21 (dotnet-single-file-embed-deps-json.exe)",
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/embedded-deps").
		ExpectsPackageStrings(expectedPkgs).
		TestCataloger(t, NewDotnetDepsBinaryCataloger(DefaultCatalogerConfig()))
}
