package plugin

import (
	"fmt"
	"github.com/anchore/syft/syft/cataloger"
	"path/filepath"
)

type Repository struct {
	byType map[Type][]Plugin
}

func NewRepository() *Repository {
	return &Repository{
		byType: make(map[Type][]Plugin),
	}
}

func NewRepositoryFromDirectory(dir string) (*Repository, error) {
	repo := NewRepository()
	if dir == "" {
		return repo, nil
	}

	return repo, repo.AddFromDirectory(dir)
}

func (c *Repository) Add(plugin Plugin) {
	c.byType[plugin.Config.Type] = append(c.byType[plugin.Config.Type], plugin)
}

func (c *Repository) AddFromDirectory(dir string, pluginTypes ...Type) error {
	plugins, err := Discover(dir, pluginTypes...)
	if err != nil {
		return err
	}
	for _, plugin := range plugins {
		c.Add(plugin)
	}
	return nil
}

func (c *Repository) Get(pluginType Type) []Plugin {
	return c.byType[pluginType]
}

func (c *Repository) ActivateCatalogers() ([]cataloger.Cataloger, func(), error) {
	var result []cataloger.Cataloger
	var plugins []Plugin
	var deactivateFn = func() {
		for _, plugin := range plugins {
			// TODO: handle error by log
			plugin.Stop()
		}
	}

	for _, plugin := range c.Get(TypeCataloger) {
		raw, err := plugin.Start()
		if err != nil {
			return nil, deactivateFn, err
		}
		plugins = append(plugins, plugin)

		theCataloger, ok := raw.(cataloger.Cataloger)
		if !ok {
			return nil, deactivateFn, fmt.Errorf("activation of cataloger did not return a cataloger object (name=%s)", plugin.Config.Name)
		}

		result = append(result, theCataloger)
	}
	return result, deactivateFn, nil
}

func Discover(dir string, pluginTypes ...Type) ([]Plugin, error) {
	var err error

	if len(pluginTypes) == 0 {
		pluginTypes = AllTypes
	}

	if !filepath.IsAbs(dir) {
		dir, err = filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
	}

	var plugins []Plugin

	for _, pluginType := range pluginTypes {
		// look into a sub dir named by the plugin type
		searchDir := filepath.Join(dir, pluginType.String())

		paths, err := filepath.Glob(filepath.Join(searchDir, "*"))
		if err != nil {
			return nil, err
		}

		for _, path := range paths {
			// TODO: should we use a config for some of this?
			plugins = append(plugins, NewPlugin(Config{
				// TODO: should the name be org/name instead of just name? this implies changing the dir storage too
				Name:    filepath.Base(path),
				Type:    pluginType,
				Command: path,
				Args:    nil, // TODO
				Env:     nil, // TODO
			}))
		}
	}
	return plugins, nil
}
