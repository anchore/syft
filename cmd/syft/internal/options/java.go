package options

import "github.com/anchore/clio"

type javaConfig struct {
	UseNetwork              bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	MavenURL                string `yaml:"maven-url" json:"maven-url" mapstructure:"maven-url"`
	MaxParentRecursiveDepth int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
}

var _ interface {
	clio.FieldDescriber
} = (*javaConfig)(nil)

func (o *javaConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.UseNetwork, `enables Syft to use the network to fill in more detailed information about artifacts
currently this enables searching maven-url for license data
when running across pom.xml files that could have more information, syft will
explicitly search maven for license information by querying the online pom when this is true
this option is helpful for when the parent pom has more data,
that is not accessible from within the final built artifact`)
	descriptions.Add(&o.MavenURL, `maven repository to use, defaults to Maven central`)
	descriptions.Add(&o.MaxParentRecursiveDepth, `depth to recursively resolve parent POMs`)
}
