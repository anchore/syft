package apkdb

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:     "obtain DB files",
			fixture:  "test-fixtures/glob-paths",
			expected: []string{"lib/apk/db/installed"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				IgnoreUnfulfilledPathResponses("etc/apk/repositories").
				TestCataloger(t, NewApkdbCataloger())
		})
	}
}
