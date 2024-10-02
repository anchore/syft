package cache

import (
	"time"

	"github.com/spf13/afero"
)

// NewInMemory returns an in-memory only cache manager
func NewInMemory(ttl time.Duration) Manager {
	if ttl <= 0 {
		return &bypassedCache{}
	}
	return &filesystemCache{
		dir: "",
		fs:  afero.NewMemMapFs(),
		ttl: ttl,
	}
}
