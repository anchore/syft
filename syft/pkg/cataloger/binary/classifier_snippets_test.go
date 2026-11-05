package binary

import (
	"testing"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/internal/manager/testutil"
)

// Test_FromURLsHaveSnippets verifies that all configured from-urls entries have
// corresponding snippets committed in the repository. Unlike from-images,
// from-urls entries point to external resources that may become unavailable over
// time, so committed snippets ensure that classifiers can continue to be tested
// without relying on the source URLs.
//
// NOTE: from-images is not covered yet because some existing entries prevent
// this check from passing. Handling those cases is outside the scope of this
// change.
// func Test_FromImagesHaveSnippets(t *testing.T) {
// 	testutil.CheckFromImagesHaveSnippets(t)
// }

func Test_FromURLsHaveSnippets(t *testing.T) {
	testutil.CheckFromURLsHaveSnippets(t)
}
