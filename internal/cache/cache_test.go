package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_SetManager(t *testing.T) {
	original := GetManager()
	defer SetManager(original)

	SetManager(nil)

	require.NotNil(t, GetManager())
	require.IsType(t, &bypassedCache{}, GetManager())

	SetManager(NewInMemory(0))

	require.NotNil(t, GetManager())
	require.IsType(t, &bypassedCache{}, GetManager())

	SetManager(NewInMemory(1 * time.Hour))

	require.NotNil(t, GetManager())
	require.IsType(t, &filesystemCache{}, GetManager())

	SetManager(nil)
	require.NotNil(t, GetManager())
	require.IsType(t, &bypassedCache{}, GetManager())
}
