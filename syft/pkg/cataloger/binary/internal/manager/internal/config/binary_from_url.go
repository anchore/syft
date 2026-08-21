package config

import (
	"fmt"
	"path"
	"path/filepath"

	"github.com/OneOfOne/xxhash"
	"go.yaml.in/yaml/v3"
)

type BinaryFromURL struct {
	GenericName   string      `yaml:"name"`
	Version       string      `yaml:"version"`
	Format        string      `yaml:"format"`          // e.g. "tar.gz" or "raw"
	PathInArchive string      `yaml:"path-in-archive"` // path within the archive to extract (required for "tar.gz")
	Targets       []URLTarget `yaml:"targets"`
}

type URLTarget struct {
	URL      string `yaml:"url"`
	Platform string `yaml:"platform"`
}

func (c BinaryFromURL) Key() string {
	return fmt.Sprintf("%s:%s", c.Name(), c.Version)
}

func (c BinaryFromURL) Name() string {
	if c.GenericName != "" {
		return c.GenericName
	}
	if len(c.Targets) > 0 {
		return path.Base(c.Targets[0].URL)
	}
	return ""
}

func (c BinaryFromURL) Filename() string {
	if c.Format == "tar.gz" && c.PathInArchive != "" {
		return path.Base(c.PathInArchive)
	}
	if len(c.Targets) > 0 {
		return path.Base(c.Targets[0].URL)
	}
	return ""
}

// StorePath returns the destination path for a downloaded binary given the
// destination root and the platform string (e.g. "linux-amd64").
func (c BinaryFromURL) StorePath(dest, platform string) string {
	return filepath.Join(dest, c.Name(), c.Version, platform, c.Filename())
}

func (c BinaryFromURL) Digest() string {
	by, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}

	hasher := xxhash.New64()
	_, _ = hasher.Write(by)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
