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
		require.NoError(t, err)
		require.Equal(t, scanner, s)
	})

	t.Run("without scanner", func(t *testing.T) {
		ctx := context.Background()
		s, err := ContextLicenseScanner(ctx)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoLicenseScanner)
		require.Nil(t, s)
	})
}
