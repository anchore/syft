package bun

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_BunLockCataloger(t *testing.T) {
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/bun-lock").
		IgnoreUnfulfilledPathResponses("**/bun.lock").
		TestCataloger(t, NewLockCataloger())
}
