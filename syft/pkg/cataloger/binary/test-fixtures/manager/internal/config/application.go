package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/scylladb/go-set/strset"
	"gopkg.in/yaml.v3"
)

const Path = "config.yaml"

type Application struct {
	DownloadPath string            `yaml:"download-path"`
	SnippetPath  string            `yaml:"snippet-path"`
	FromImages   []BinaryFromImage `yaml:"from-images"`
}

func DefaultApplication() Application {
	return Application{
		DownloadPath: "bin",
	}
}

func Read() (*Application, error) {
	return read(Path)
}

func read(path string) (*Application, error) {
	appConfig := DefaultApplication()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &appConfig)
	if err != nil {
		return nil, err
	}

	if err := appConfig.Validate(); err != nil {
		return nil, err
	}
	return &appConfig, nil
}

func (c Image) Key() string {
	return fmt.Sprintf("%s:%s", c.Reference, c.Platform)
}

func (c Application) Validate() error {
	set := strset.New()
	var err error
	for i, entry := range c.FromImages {
		key := entry.Key()

		if set.Has(key) {
			err = multierror.Append(err, fmt.Errorf("duplicate entry %q", entry))
			continue
		}

		set.Add(entry.Key())

		if len(entry.PathsInImage) > 1 && entry.GenericName == "" {
			err = multierror.Append(err, fmt.Errorf("specified multiple paths but no name for entry %d (%s)", i+1, key))
		}
		if entry.Name() == "" {
			err = multierror.Append(err, fmt.Errorf("missing name for entry %d", i+1))
		}
		if entry.Version == "" {
			err = multierror.Append(err, fmt.Errorf("missing version for entry %d", i+1))
		}
		if len(entry.Images) == 0 {
			err = multierror.Append(err, fmt.Errorf("missing images for entry %d (%s)", i+1, key))
		}

		var imageSet = strset.New()
		for j, image := range entry.Images {
			imgKey := image.Key()
			if imageSet.Has(imgKey) {
				err = multierror.Append(err, fmt.Errorf("duplicate image %q for entry %d (%s)", image.Key(), i+1, key))
				continue
			}
			imageSet.Add(imgKey)

			if image.Reference == "" {
				err = multierror.Append(err, fmt.Errorf("missing ref reference for entry %d (%s) image %d", i+1, key, j+1))
			}
			if image.Platform == "" {
				err = multierror.Append(err, fmt.Errorf("missing platform for entry %d (%s) image %d", i+1, key, j+1))
			}
		}
		if len(entry.PathsInImage) == 0 {
			err = multierror.Append(err, fmt.Errorf("missing paths for entry %d (%s)", i+1, key))
		}
	}
	return err
}

func (c Application) GetBinaryFromImage(name, version string) *BinaryFromImage {
	if strings.Contains(name, "@") && version == "" {
		parts := strings.Split(name, "@")
		name = parts[0]
		version = parts[1]
	}
	for _, entry := range c.FromImages {
		if entry.Name() == name && entry.Version == version {
			return &entry
		}
	}
	return nil
}

func (c Application) GetBinaryFromImageByPath(storePath string) *BinaryFromImage {
	// each key is the store path except for the root (e.g. bin or snippet)
	entryByStorePath := make(map[string]BinaryFromImage)

	for _, entry := range c.FromImages {
		for _, path := range entry.AllStorePaths(c.DownloadPath) {
			pathWithoutRoot := splitFilepath(path)[1:]
			entryByStorePath[filepath.Join(pathWithoutRoot...)] = entry
		}
	}

	pathWithoutRoot := filepath.Join(splitFilepath(storePath)[1:]...)
	if entry, ok := entryByStorePath[pathWithoutRoot]; ok {
		return &entry
	}

	return nil
}

func splitFilepath(path string) []string {
	return strings.Split(path, string(filepath.Separator))
}
