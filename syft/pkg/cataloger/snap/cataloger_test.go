package snap

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "base snap with dpkg.yaml",
			fixture: "test-fixtures/glob-paths/base",
		},
		{
			name:    "system snap with manifest.yaml",
			fixture: "test-fixtures/glob-paths/system",
		},
		{
			name:    "snap with meta/snap.yaml",
			fixture: "test-fixtures/glob-paths/meta",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				IgnoreUnfulfilledPathResponses("**/meta/snap.yaml", "**/usr/share/snappy/dpkg.yaml", "**/doc/linux-modules-*/changelog.Debian.gz", "**/snap/manifest.yaml", "**/snap/snapcraft.yaml").
				TestCataloger(t, NewCataloger())
		})
	}
}
