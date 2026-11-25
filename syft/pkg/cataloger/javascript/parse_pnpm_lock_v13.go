package javascript

import (
	"fmt"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/log"
)

type pnpmV13LockYaml struct {
	Packages map[string]pnpmV13PackageEntry `yaml:"packages"`
}

type pnpmV13PackageEntry struct {
	Integrity            string `yaml:"integrity"`
	Version              string `yaml:"version"`
	pnpmV13DependencySet `yaml:",inline"`
	Snapshots            []pnpmV13DependencySet `yaml:"snapshots"`
}

type pnpmV13DependencySet struct {
	Dependencies         map[string]pnpmV13Reference `yaml:"dependencies"`
	OptionalDependencies map[string]pnpmV13Reference `yaml:"optionalDependencies"`
	PeerDependencies     map[string]pnpmV13Reference `yaml:"peerDependencies"`
}

type pnpmV13Reference struct {
	Version string `yaml:"version"`
	Below   bool   `yaml:"below"`
	text    string
}

func (r *pnpmV13Reference) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		return node.Decode(&r.text)
	}
	type mapping pnpmV13Reference
	return node.Decode((*mapping)(r))
}

func (p *pnpmV13LockYaml) Parse(_ float64, doc *yaml.Node) ([]pnpmPackage, error) {
	if err := doc.Decode(p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pnpm v13 lockfile: %w", err)
	}

	var packages []pnpmPackage
	for key, entry := range sortedIter(p.Packages) {
		name, version, ok := parsePnpmPackageKey(key, "@")
		if !ok {
			log.WithFields("key", key).Trace("unable to parse pnpm v13 package key")
			continue
		}
		if entry.Version != "" {
			version = entry.Version
		}

		dependencies := make(map[string]string)
		entry.addTo(dependencies)
		// Package entries carry the shared graph. Nested snapshots add the
		// dependencies that vary by peer context.
		for _, snapshot := range entry.Snapshots {
			snapshot.addTo(dependencies)
		}
		packages = append(packages, pnpmPackage{
			Name: name, Version: version, Integrity: entry.Integrity, Dependencies: dependencies,
		})
	}
	return packages, nil
}

func (d pnpmV13DependencySet) addTo(dependencies map[string]string) {
	// A scalar peer entry is a declared range. Only mapped entries carry a
	// resolved version, and "below" bindings belong to transitive dependencies.
	for name, ref := range d.PeerDependencies {
		if ref.Version != "" && !ref.Below {
			dependencies[name] = ref.Version
		}
	}
	for _, refs := range []map[string]pnpmV13Reference{d.OptionalDependencies, d.Dependencies} {
		for name, ref := range refs {
			version := ref.Version
			if version == "" {
				version = ref.text
			}
			if version != "" {
				dependencies[name] = version
			}
		}
	}
}
