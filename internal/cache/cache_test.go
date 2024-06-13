package cache

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_SetManager(t *testing.T) {
	original := GetManager()
	defer SetManager(original)

	SetManager(NewInMemory(0))

	require.NotNil(t, GetManager())
	require.IsType(t, &filesystemCache{}, GetManager())

	SetManager(nil)
	require.NotNil(t, GetManager())
	require.IsType(t, &bypassedCache{}, GetManager())
}
