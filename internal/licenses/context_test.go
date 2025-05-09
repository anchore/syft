package licenses

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetContextLicenseScanner(t *testing.T) {
	scanner := testScanner()
	ctx := context.Background()
	ctx = SetContextLicenseScanner(ctx, scanner)

	val := ctx.Value(ctxKey)
	require.NotNil(t, val)
	s, ok := val.(Scanner)
	require.True(t, ok)
	require.Equal(t, scanner, s)
}

func TestIsContextLicenseScannerSet(t *testing.T) {
	scanner := testScanner()
	ctx := context.Background()
	require.False(t, IsContextLicenseScannerSet(ctx))

	ctx = SetContextLicenseScanner(ctx, scanner)
	require.True(t, IsContextLicenseScannerSet(ctx))
}

func TestContextLicenseScanner(t *testing.T) {
	t.Run("with scanner", func(t *testing.T) {
		scanner := testScanner()
		ctx := SetContextLicenseScanner(context.Background(), scanner)
		s, err := ContextLicenseScanner(ctx)
		if err != nil || s != scanner {
			t.Fatal("expected scanner from context")
		}
	})

	t.Run("without scanner", func(t *testing.T) {
		ctx := context.Background()
		s, err := ContextLicenseScanner(ctx)
		if err != nil || s == nil {
			t.Fatal("expected default scanner")
		}
	})
}
