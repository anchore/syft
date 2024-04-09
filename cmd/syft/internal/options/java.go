package options

import "github.com/anchore/syft/syft/pkg/cataloger/java"

type javaConfig struct {
	UseNetwork              bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	UseMavenLocalRepository bool   `yaml:"use-maven-localrepository" json:"use-maven-localrepository" mapstructure:"use-maven-localrepository"`
	MavenLocalRepositoryDir string `yaml:"maven-localrepository-dir" json:"maven-localrepository-dir" mapstructure:"maven-localrepository-dir"`
	MavenURL                string `yaml:"maven-url" json:"maven-url" mapstructure:"maven-url"`
}

func defaultJavaConfig() javaConfig {
	def := java.DefaultArchiveCatalogerConfig()

	return javaConfig{
		UseNetwork:              def.UseNetwork,
		UseMavenLocalRepository: def.UseMavenLocalRepository,
		MavenLocalRepositoryDir: def.MavenLocalRepositoryDir,
		MavenURL:                def.MavenBaseURL,
	}
}
