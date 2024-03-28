package java

import "github.com/anchore/syft/syft/cataloging"

const mavenBaseURL = "https://repo1.maven.org/maven2"
const mavenCommand = "mvn"

type ArchiveCatalogerConfig struct {
	cataloging.ArchiveSearchConfig `yaml:",inline" json:"" mapstructure:",squash"`
	UseNetwork                     bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	UseMaven                       bool   `yaml:"use-maven" json:"use-maven" mapstructure:"use-maven"`
	MavenCommand                   string `yaml:"maven-command" json:"maven-command" mapstructure:"maven-command"`
	MavenBaseURL                   string `yaml:"maven-base-url" json:"maven-base-url" mapstructure:"maven-base-url"`
	MaxParentRecursiveDepth        int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
}

func DefaultArchiveCatalogerConfig() ArchiveCatalogerConfig {
	return ArchiveCatalogerConfig{
		ArchiveSearchConfig:     cataloging.DefaultArchiveSearchConfig(),
		UseNetwork:              false,
		UseMaven:                true,
		MavenCommand:            mavenCommand,
		MavenBaseURL:            mavenBaseURL,
		MaxParentRecursiveDepth: 5,
	}
}

func (j ArchiveCatalogerConfig) WithUseNetwork(input bool) ArchiveCatalogerConfig {
	j.UseNetwork = input
	return j
}

func (j ArchiveCatalogerConfig) WithUseMaven(input bool) ArchiveCatalogerConfig {
	j.UseMaven = input
	return j
}

func (j ArchiveCatalogerConfig) WithMavenCommand(input string) ArchiveCatalogerConfig {
	if input != "" {
		j.MavenCommand = input
	}
	return j
}

func (j ArchiveCatalogerConfig) WithMavenBaseURL(input string) ArchiveCatalogerConfig {
	if input != "" {
		j.MavenBaseURL = input
	}
	return j
}

func (j ArchiveCatalogerConfig) WithArchiveTraversal(search cataloging.ArchiveSearchConfig, maxDepth int) ArchiveCatalogerConfig {
	if maxDepth > 0 {
		j.MaxParentRecursiveDepth = maxDepth
	}
	j.ArchiveSearchConfig = search
	return j
}
