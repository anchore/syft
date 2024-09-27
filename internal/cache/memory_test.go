package cache

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal"
)

func Test_NewInMemory(t *testing.T) {
	man := NewInMemory(time.Hour)

	cacheName := "test"
	cacheVersion := "v1"
	cache := man.GetCache(cacheName, cacheVersion)

	cacheKey := "test-key"
	contentsValue := "some contents to cache"

	err := cache.Write(cacheKey, strings.NewReader(contentsValue))
	require.NoError(t, err)

	rdr, err := cache.Read(cacheKey)
	require.NoError(t, err)
	defer internal.CloseAndLogError(rdr, cacheKey)

	contents, err := io.ReadAll(rdr)
	require.NoError(t, err)
	require.Equal(t, contentsValue, string(contents))

	_, err = cache.Read("otherKey")
	require.ErrorIs(t, err, errNotFound)
}
