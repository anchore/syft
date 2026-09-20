package java

import (
	"strings"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

type ArchiveCatalogerConfig struct {
	cataloging.ArchiveSearchConfig `yaml:",inline" json:"" mapstructure:",squash"`

	// 	UseNetwork enables network operations for java package metadata enrichment, such as fetching parent POMs and license information.
	// app-config: java.use-network
	UseNetwork bool `yaml:"use-network" json:"use-network" mapstructure:"use-network"`

	// UseMavenLocalRepository enables searching the local maven repository (`~/.m2/repository` by default) for parent POMs and other metadata.
	// app-config: java.use-maven-local-repository
	UseMavenLocalRepository bool `yaml:"use-maven-localrepository" json:"use-maven-localrepository" mapstructure:"use-maven-localrepository"`

	// MavenLocalRepositoryDir specifies the location of the local maven repository. When not set, defaults to `~/.m2/repository`.
	// app-config: java.maven-local-repository-dir
	MavenLocalRepositoryDir string `yaml:"maven-localrepository-dir" json:"maven-localrepository-dir" mapstructure:"maven-localrepository-dir"`

	// MavenBaseURL specifies the base URL(s) to use for fetching POMs and metadata from maven central or other repositories. When not set, defaults to `https://repo1.maven.org/maven2`.
	// app-config: java.maven-url
	MavenBaseURL string `yaml:"maven-base-url" json:"maven-base-url" mapstructure:"maven-base-url"`

	// MaxParentRecursiveDepth limits how many parent POMs will be fetched recursively before stopping. This prevents fetching excessively deep parent graphs.
	// app-config: java.max-parent-recursive-depth
	MaxParentRecursiveDepth int `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`

	// ResolveTransitiveDependencies enables resolving transitive dependencies for java packages found within archives.
	// app-config: java.resolve-transitive-dependencies
	ResolveTransitiveDependencies bool `yaml:"resolve-transitive-dependencies" json:"resolve-transitive-dependencies" mapstructure:"resolve-transitive-dependencies"`

	// NestedArchivesHandledExternally indicates that another mechanism owns recursion into nested
	// archives, so this cataloger must not unarchive them itself. It has no yaml/json/mapstructure
	// key, so no config file, flag or environment variable reaches it.
	//
	// Only syft.CreateSBOMConfig writes it, deriving it from the nested-archive cataloging depth so
	// the two cannot disagree. Callers building this config should leave it alone; the zero value
	// recurses, this cataloger's default.
	NestedArchivesHandledExternally bool `yaml:"-" json:"-" mapstructure:"-"`
}

func DefaultArchiveCatalogerConfig() ArchiveCatalogerConfig {
	mavenCfg := maven.DefaultConfig()
	return ArchiveCatalogerConfig{
		ArchiveSearchConfig:           cataloging.DefaultArchiveSearchConfig(),
		UseNetwork:                    mavenCfg.UseNetwork,
		UseMavenLocalRepository:       mavenCfg.UseLocalRepository,
		MavenLocalRepositoryDir:       mavenCfg.LocalRepositoryDir,
		MavenBaseURL:                  strings.Join(mavenCfg.Repositories, ","),
		MaxParentRecursiveDepth:       mavenCfg.MaxParentRecursiveDepth,
		ResolveTransitiveDependencies: false,
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

func (j ArchiveCatalogerConfig) WithResolveTransitiveDependencies(resolveTransitiveDependencies bool) ArchiveCatalogerConfig {
	j.ResolveTransitiveDependencies = resolveTransitiveDependencies
	return j
}

func (j ArchiveCatalogerConfig) WithArchiveTraversal(search cataloging.ArchiveSearchConfig, maxDepth int) ArchiveCatalogerConfig {
	j.MaxParentRecursiveDepth = maxDepth
	j.ArchiveSearchConfig = search
	return j
}

func (j ArchiveCatalogerConfig) mavenConfig() maven.Config {
	return maven.Config{
		UseNetwork:              j.UseNetwork,
		UseLocalRepository:      j.UseMavenLocalRepository,
		LocalRepositoryDir:      j.MavenLocalRepositoryDir,
		Repositories:            strings.Split(j.MavenBaseURL, ","),
		MaxParentRecursiveDepth: j.MaxParentRecursiveDepth,
	}
}
