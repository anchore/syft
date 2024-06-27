package options

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/source/sourceproviders"
)

type sourceConfig struct {
	Name     string      `json:"name" yaml:"name" mapstructure:"name"`
	Version  string      `json:"version" yaml:"version" mapstructure:"version"`
	BasePath string      `yaml:"base-path" json:"base-path" mapstructure:"base-path"` // specify base path for all file paths
	File     fileSource  `json:"file" yaml:"file" mapstructure:"file"`
	Image    imageSource `json:"image" yaml:"image" mapstructure:"image"`
}

type fileSource struct {
	Digests []string `json:"digests" yaml:"digests" mapstructure:"digests"`
}

var _ interface {
	clio.FieldDescriber
} = (*sourceConfig)(nil)

func (o *sourceConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.File.Digests, `the file digest algorithms to use on the scanned file (options: "md5", "sha1", "sha224", "sha256", "sha384", "sha512")`)
	descriptions.Add(&o.Image.DefaultPullSource, `allows users to specify which image source should be used to generate the sbom
valid values are: registry, docker, podman`)
}

type imageSource struct {
	DefaultPullSource string `json:"default-pull-source" yaml:"default-pull-source" mapstructure:"default-pull-source"`
}

func defaultSourceConfig() sourceConfig {
	var digests []string
	for _, alg := range sourceproviders.DefaultConfig().DigestAlgorithms {
		digests = append(digests, alg.String())
	}
	return sourceConfig{
		File: fileSource{
			Digests: digests,
		},
	}
}

func (c *fileSource) PostLoad() error {
	digests := strset.New(c.Digests...).List()
	sort.Strings(digests)
	c.Digests = digests
	return nil
}

func (c imageSource) PostLoad() error {
	return checkDefaultSourceValues(c.DefaultPullSource)
}

var validDefaultSourceValues = []string{"registry", "docker", "podman", ""}

func checkDefaultSourceValues(source string) error {
	validValues := strset.New(validDefaultSourceValues...)
	if !validValues.Has(source) {
		validValuesString := strings.Join(validDefaultSourceValues, ", ")
		return fmt.Errorf("%s is not a valid default source; please use one of the following: %s''", source, validValuesString)
	}

	return nil
}
