package snapsource

import (
	"errors"
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

// errNoManifest means the payload is a readable squashfs that simply does not carry a snap manifest.
// This is distinct from a manifest that is present but unusable, and callers are expected to treat
// the two differently.
var errNoManifest = errors.New("no snap manifest file found")

func parseManifest(resolver file.Resolver) (*snapManifest, error) {
	locations, err := resolver.FilesByPath(manifestLocation)
	if err != nil {
		return nil, fmt.Errorf("unable to find snap manifest file: %w", err)
	}

	if len(locations) == 0 {
		return nil, errNoManifest
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

	// note: name and version are deliberately not validated here. a manifest that decoded but is
	// missing them still carries usable fields (summary, base, grade, ...) and throwing it away would
	// describe less than we know. the caller surfaces the missing identity.
	return &manifest, nil
}
