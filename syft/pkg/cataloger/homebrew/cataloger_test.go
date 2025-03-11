package homebrew

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_HomebrewCataloger_Globs(t *testing.T) {
	fixture := "test-fixtures/glob-paths"

	expected := []string{
		"Cellar/foo/1.2.3/.brew/foo.rb",
		"Homebrew/Library/Taps/testorg/sometap/Formula/bar.rb",
	}

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsResolverContentQueries(expected).
		TestCataloger(t, NewCataloger())
}
