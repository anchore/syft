package dart

import (
	"fmt"
	"io"
	"net/url"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"gopkg.in/yaml.v2"
)

// integrity check
var _ common.ParserFn = parsePubspecLock

const defaultPubRegistry string = "https://pub.dartlang.org"

type pubspecLock struct {
	Packages map[string]pubspecLockPackage `yaml:"packages"`
	Sdks     map[string]string             `yaml:"sdks"`
}

type pubspecLockPackage struct {
	Dependency  string                 `yaml:"dependency" mapstructure:"dependency"`
	Description pubspecLockDescription `yaml:"description" mapstructure:"description"`
	Source      string                 `yaml:"source" mapstructure:"source"`
	Version     string                 `yaml:"version" mapstructure:"version"`
}

type pubspecLockDescription struct {
	Name        string `yaml:"name" mapstructure:"name"`
	URL         string `yaml:"url" mapstructure:"url"`
	Path        string `yaml:"path" mapstructure:"path"`
	Ref         string `yaml:"ref" mapstructure:"ref"`
	ResolvedRef string `yaml:"resolved-ref" mapstructure:"resolved-ref"`
}

func parsePubspecLock(path string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	var packages []*pkg.Package

	dec := yaml.NewDecoder(reader)

	var p pubspecLock
	if err := dec.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("failed to parse pubspec.lock file: %w", err)
	}

	for name, pubPkg := range p.Packages {
		packages = append(packages, newPubspecLockPackage(name, pubPkg))
	}

	return packages, nil, nil
}

func newPubspecLockPackage(name string, p pubspecLockPackage) *pkg.Package {
	return &pkg.Package{
		Name:         name,
		Version:      p.Version,
		Language:     pkg.Dart,
		Type:         pkg.DartPubPkg,
		MetadataType: pkg.DartPubMetadataType,
		Metadata: &pkg.DartPubMetadata{
			Name:      name,
			Version:   p.Version,
			HostedURL: p.getHostedURL(),
			VcsURL:    p.getVcsURL(),
		},
	}
}

func (p *pubspecLockPackage) getVcsURL() string {
	if p.Source == "git" {
		if p.Description.Path == "." {
			return fmt.Sprintf("%s@%s", p.Description.URL, p.Description.ResolvedRef)
		}

		return fmt.Sprintf("%s@%s#%s", p.Description.URL, p.Description.ResolvedRef, p.Description.Path)
	}

	return ""
}

func (p *pubspecLockPackage) getHostedURL() string {
	if p.Source == "hosted" && p.Description.URL != defaultPubRegistry {
		u, err := url.Parse(p.Description.URL)
		if err != nil {
			log.Debugf("Unable to parse registry url %w", err)
			return p.Description.URL
		}
		return u.Host
	}

	return ""
}
