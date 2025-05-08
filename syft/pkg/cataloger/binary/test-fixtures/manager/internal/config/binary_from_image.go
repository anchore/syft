package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/OneOfOne/xxhash"
	"gopkg.in/yaml.v3"
)

type BinaryFromImage struct {
	GenericName string `yaml:"name"`
	Version     string `yaml:"version"`

	Images       []Image  `yaml:"images"`
	PathsInImage []string `yaml:"paths"`
}

type Image struct {
	Reference string `yaml:"ref"`
	Platform  string `yaml:"platform"`
}

func (c BinaryFromImage) Key() string {
	return fmt.Sprintf("%s:%s", c.Name(), c.Version)
}

func (c BinaryFromImage) Name() string {
	displayName := c.GenericName
	if displayName == "" {
		var path string
		if len(c.PathsInImage) > 0 {
			path = c.PathsInImage[0]
		}
		if path == "" {
			return ""
		}
		return filepath.Base(path)
	}
	return displayName
}

func (c BinaryFromImage) AllStorePaths(dest string) []string {
	var paths []string
	for _, image := range c.Images {
		paths = append(paths, c.AllStorePathsForImage(image, dest)...)
	}
	return paths
}

func (c BinaryFromImage) AllStorePathsForImage(image Image, dest string) []string {
	var paths []string

	platform := PlatformAsValue(image.Platform)
	for _, path := range c.PathsInImage {
		base := filepath.Base(path)
		if path == "" {
			base = ""
		}
		paths = append(paths, filepath.Join(dest, c.Name(), c.Version, platform, base))
	}

	return paths
}

func PlatformAsValue(platform string) string {
	return strings.ReplaceAll(platform, "/", "-")
}

func (c BinaryFromImage) Digest() string {
	by, err := yaml.Marshal(c)
	if err != nil {
		panic(err)
	}

	hasher := xxhash.New64()
	_, _ = hasher.Write(by)
	return fmt.Sprintf("%x", hasher.Sum(nil))
}
