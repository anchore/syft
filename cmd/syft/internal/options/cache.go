package options

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"

	"github.com/anchore/clio"
	"github.com/anchore/syft/internal/cache"
	"github.com/anchore/syft/internal/log"
)

// Cache provides configuration for the Syft caching behavior
type Cache struct {
	Dir string `yaml:"dir" mapstructure:"dir"`
	TTL string `yaml:"ttl" mapstructure:"ttl"`
}

func (c *Cache) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&c.Dir, "root directory to cache any downloaded content; empty string will use an in-memory cache")
	descriptions.Add(&c.TTL, "time to live for cached data; setting this to 0 will disable caching entirely")
}

func (c *Cache) PostLoad() error {
	ttl, err := parseDuration(c.TTL)
	if err != nil {
		log.Warnf("unable to parse duration '%v', using default (%s) due to: %v", c.TTL, durationToString(defaultTTL()), err)
		ttl = defaultTTL()
	}
	// if TTL is <= 0, disable caching entirely
	if ttl <= 0 {
		cache.SetManager(nil)
		return nil
	}
	// if dir == "" but we have a TTL, use an in-memory cache
	if c.Dir == "" {
		cache.SetManager(cache.NewInMemory(ttl))
		return nil
	}
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
	return nil
}

var _ interface {
	clio.PostLoader
	clio.FieldDescriber
} = (*Cache)(nil)

func DefaultCache() Cache {
	return Cache{
		Dir: defaultDir(),
		TTL: durationToString(defaultTTL()),
	}
}

func defaultTTL() time.Duration {
	return 7 * 24 * time.Hour
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

func durationToString(duration time.Duration) string {
	days := int64(duration / (24 * time.Hour))
	remain := duration % (24 * time.Hour)
	out := ""
	if days > 0 {
		out = fmt.Sprintf("%vd", days)
	}
	if remain != 0 {
		out += remain.String()
	}
	if out == "" {
		return "0"
	}
	return out
}

func parseDuration(duration string) (time.Duration, error) {
	whitespace := regexp.MustCompile(`\s+`)
	duration = strings.ToLower(whitespace.ReplaceAllString(duration, ""))
	parts := strings.SplitN(duration, "d", 2)
	var days time.Duration
	var remain time.Duration
	var err error
	if len(parts) > 1 {
		numDays, daysErr := strconv.Atoi(parts[0])
		if daysErr != nil {
			return 0, daysErr
		}
		days = time.Duration(numDays) * 24 * time.Hour
		if len(parts[1]) > 0 {
			remain, err = time.ParseDuration(parts[1])
		}
	} else {
		remain, err = time.ParseDuration(duration)
	}
	return days + remain, err
}
