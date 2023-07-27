package fileresolver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
)

func Test_NewDeferredResolver(t *testing.T) {
	creatorCalled := false

	deferredResolver := NewDeferred(func() (file.Resolver, error) {
		creatorCalled = true
		return file.NewMockResolverForPaths(), nil
	})

	require.False(t, creatorCalled)
	require.Nil(t, deferredResolver.resolver)

	_, _ = deferredResolver.FilesByGlob("**/*")

	require.True(t, creatorCalled)
	require.NotNil(t, deferredResolver.resolver)
}
