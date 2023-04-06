package source

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NewDeferredResolver(t *testing.T) {
	creatorCalled := false

	deferredResolver := NewDeferredResolver(func() (FileResolver, error) {
		creatorCalled = true
		return NewMockResolverForPaths(), nil
	})

	require.False(t, creatorCalled)
	require.Nil(t, deferredResolver.resolver)

	_, _ = deferredResolver.FilesByGlob("**/*")

	require.True(t, creatorCalled)
	require.NotNil(t, deferredResolver.resolver)
}
