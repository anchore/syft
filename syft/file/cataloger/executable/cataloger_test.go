package executable

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/file"
)

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("boom") }

type panickingContentsResolver struct {
	*file.MockResolver
}

func (r panickingContentsResolver) FilesByMIMEType(...string) ([]file.Location, error) {
	return r.FilesByPath("cataloger_test.go")
}

func (r panickingContentsResolver) FileContentsByLocation(file.Location) (io.ReadCloser, error) {
	return io.NopCloser(panicReader{}), nil
}

func TestCatalogCtx_panicBecomesUnknown(t *testing.T) {
	resolver := panickingContentsResolver{file.NewMockResolverForPaths("cataloger_test.go")}

	results, err := NewCataloger(DefaultConfig()).CatalogCtx(context.Background(), resolver)

	require.Empty(t, results)
	unknowns, remaining := unknown.ExtractCoordinateErrors(err)
	require.NoError(t, remaining)
	require.Len(t, unknowns, 1)
	require.ErrorContains(t, unknowns[0].Reason, "recovered from panic while reading executable: boom")
}
