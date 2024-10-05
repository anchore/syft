package cachemanager_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/go-cache"
	"github.com/anchore/syft/internal/cachemanager"
)

func Test_Set(t *testing.T) {
	original := cachemanager.Get()
	defer cachemanager.Set(original)

	cachemanager.Set(nil)

	require.NotNil(t, cachemanager.Get())
	require.IsType(t, cache.NewBypassed(), cachemanager.Get())

	cachemanager.Set(cache.NewInMemory(0))

	require.NotNil(t, cachemanager.Get())
	require.IsType(t, cache.NewBypassed(), cachemanager.Get())

	cachemanager.Set(cache.NewInMemory(1 * time.Hour))

	require.NotNil(t, cachemanager.Get())

	typ, err := cache.NewFromDir(nil, t.TempDir(), time.Hour)
	require.NoError(t, err)
	require.IsType(t, typ, cachemanager.Get())

	cachemanager.Set(nil)
	require.NotNil(t, cachemanager.Get())
	require.IsType(t, cache.NewBypassed(), cachemanager.Get())
}
