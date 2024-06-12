package options

import (
	"os"
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
)

// Cache provides configuration for the Syft caching behavior
type Cache struct {
	Dir string        `yaml:"dir" mapstructure:"dir"`
	TTL time.Duration `yaml:"ttl" mapstructure:"ttl"`
}

func (c *Cache) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&c.Dir, "root directory to cache any downloaded content")
	descriptions.Add(&c.TTL, "time to live for cached data")
}

func (c *Cache) PostLoad() error {
	if c.Dir != "" {
		ttl := c.TTL
		dir, err := homedir.Expand(c.Dir)
		if err != nil {
			log.Warnf("unable to expand cache directory %s: %v", c.Dir, err)
			cache.SetManager(cache.NewInMemory(ttl))
		} else {
			m, err := cache.NewFromDir(dir, ttl)
			if err != nil {
				log.Warnf("unable to get filesystem cache at %s: %v", c.Dir, err)
				cache.SetManager(cache.NewInMemory(ttl))
			} else {
				cache.SetManager(m)
			}
		}
	}
	return nil
}

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*Cache)(nil)

func DefaultCache() Cache {
	return Cache{
		Dir: defaultDir(),
		TTL: 7 * 24 * time.Hour,
	}
}

func defaultDir() string {
	var err error
	cacheRoot := xdg.CacheHome
	if cacheRoot == "" {
		cacheRoot, err = homedir.Dir()
		if err != nil {
			cacheRoot = os.TempDir()
			log.Debugf("unable to get stable cache directory due to: %v, defaulting cache to temp dir: %s", err, cacheRoot)
		} else {
			cacheRoot = filepath.Join(cacheRoot, ".cache")
		}
	}

	return filepath.Join(cacheRoot, "syft")
}
