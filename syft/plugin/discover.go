package plugin

import "path/filepath"

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
