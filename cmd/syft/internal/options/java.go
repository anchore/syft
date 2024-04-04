package options

import "github.com/anchore/syft/syft/pkg/cataloger/java"

type javaConfig struct {
	UseNetwork              bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	UseMavenLocalRepository bool   `yaml:"use-maven-localrepository" json:"use-maven-localrepository" mapstructure:"use-maven-localrepository"`
	MavenURL                string `yaml:"maven-url" json:"maven-url" mapstructure:"maven-url"`
	MaxParentRecursiveDepth int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
}

func defaultJavaConfig() javaConfig {
	def := java.DefaultArchiveCatalogerConfig()

	return javaConfig{
		UseNetwork:              def.UseNetwork,
		UseMavenLocalRepository: def.UseMavenLocalRepository,
		MavenURL:                def.MavenBaseURL,
		MaxParentRecursiveDepth: def.MaxParentRecursiveDepth,
	}
}
