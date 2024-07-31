package java

import "github.com/anchore/syft/syft/cataloging"

const mavenBaseURL = "https://repo1.maven.org/maven2"

type ArchiveCatalogerConfig struct {
	cataloging.ArchiveSearchConfig `yaml:",inline" json:"" mapstructure:",squash"`
	UseNetwork                     bool   `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	UseMavenLocalRepository        bool   `yaml:"use-maven-localrepository" json:"use-maven-localrepository" mapstructure:"use-maven-localrepository"`
	MavenLocalRepositoryDir        string `yaml:"maven-localrepository-dir" json:"maven-localrepository-dir" mapstructure:"maven-localrepository-dir"`
	MavenBaseURL                   string `yaml:"maven-base-url" json:"maven-base-url" mapstructure:"maven-base-url"`
	MaxParentRecursiveDepth        int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
}

func DefaultArchiveCatalogerConfig() ArchiveCatalogerConfig {
	return ArchiveCatalogerConfig{
		ArchiveSearchConfig:     cataloging.DefaultArchiveSearchConfig(),
		UseNetwork:              false,
		UseMavenLocalRepository: false,
		MavenLocalRepositoryDir: defaultMavenLocalRepoDir(),
		MavenBaseURL:            mavenBaseURL,
		MaxParentRecursiveDepth: 0, // unlimited
	}
}

func (j ArchiveCatalogerConfig) WithUseNetwork(input bool) ArchiveCatalogerConfig {
	j.UseNetwork = input
	return j
}

func (j ArchiveCatalogerConfig) WithUseMavenLocalRepository(input bool) ArchiveCatalogerConfig {
	j.UseMavenLocalRepository = input
	return j
}

func (j ArchiveCatalogerConfig) WithMavenLocalRepositoryDir(input string) ArchiveCatalogerConfig {
	j.MavenLocalRepositoryDir = input
	return j
}

func (j ArchiveCatalogerConfig) WithMavenBaseURL(input string) ArchiveCatalogerConfig {
	if input != "" {
		j.MavenBaseURL = input
	}
	return j
}

func (j ArchiveCatalogerConfig) WithArchiveTraversal(search cataloging.ArchiveSearchConfig, maxDepth int) ArchiveCatalogerConfig {
	j.MaxParentRecursiveDepth = maxDepth
	j.ArchiveSearchConfig = search
	return j
}
