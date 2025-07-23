package testutil

import (
	"testing"

	"github.com/anchore/syft/syft/internal/packagemetadata"
	"github.com/anchore/syft/syft/internal/sourcemetadata"
)

type PackageMetadataCompletionTester struct {
	*packagemetadata.CompletionTester
}

type SourceMetadataCompletionTester struct {
	*sourcemetadata.CompletionTester
}

func NewPackageMetadataCompletionTester(t testing.TB, ignore ...any) *PackageMetadataCompletionTester {
	t.Helper()
	return &PackageMetadataCompletionTester{
		CompletionTester: packagemetadata.NewCompletionTester(t, ignore...),
	}
}

func NewSourceMetadataCompletionTester(t testing.TB, ignore ...any) *SourceMetadataCompletionTester {
	t.Helper()
	return &SourceMetadataCompletionTester{
		CompletionTester: sourcemetadata.NewCompletionTester(t, ignore...),
	}
}
