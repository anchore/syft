package snapsource

import (
	"fmt"

	"github.com/goccy/go-yaml"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
)

type snapManifest struct {
	Name          string   `yaml:"name"`
	Version       string   `yaml:"version"`
	Summary       string   `yaml:"summary"`
	Base          string   `yaml:"base"`
	Grade         string   `yaml:"grade"`
	Confinement   string   `yaml:"confinement"`
	Architectures []string `yaml:"architectures"`
}

const manifestLocation = "/meta/snap.yaml"

func parseManifest(resolver file.Resolver) (*snapManifest, error) {
	locations, err := resolver.FilesByPath(manifestLocation)
	if err != nil {
		return nil, fmt.Errorf("unable to find snap manifest file: %w", err)
	}

	if len(locations) == 0 {
		return nil, fmt.Errorf("no snap manifest file found")
	}

	if len(locations) > 1 {
		return nil, fmt.Errorf("multiple snap manifest files found")
	}

	manifestFile := locations[0]

	reader, err := resolver.FileContentsByLocation(manifestFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read snap manifest file: %w", err)
	}
	defer internal.CloseAndLogError(reader, manifestFile.RealPath)

	var manifest snapManifest
	if err := yaml.NewDecoder(reader).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("unable to decode snap manifest file: %w", err)
	}

	if manifest.Name == "" || manifest.Version == "" {
		return nil, fmt.Errorf("invalid snap manifest file: missing name or version")
	}

	return &manifest, nil
}
