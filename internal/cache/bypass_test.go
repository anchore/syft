package cache

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_bypassedCache(t *testing.T) {
	m := bypassedCache{}
	cache := m.GetCache("name", "version")
	err := cache.Write("test", strings.NewReader("value"))
	require.NoError(t, err)
	rdr, err := cache.Read("test")
	require.Nil(t, rdr)
	require.ErrorIs(t, err, errNotFound)
}
