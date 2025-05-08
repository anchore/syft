package options

import (
	"github.com/anchore/clio"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
)

type javaConfig struct {
	UseNetwork                    *bool  `yaml:"use-network" json:"use-network" mapstructure:"use-network"`
	UseMavenLocalRepository       *bool  `yaml:"use-maven-local-repository" json:"use-maven-local-repository" mapstructure:"use-maven-local-repository"`
	MavenLocalRepositoryDir       string `yaml:"maven-local-repository-dir" json:"maven-local-repository-dir" mapstructure:"maven-local-repository-dir"`
	MavenURL                      string `yaml:"maven-url" json:"maven-url" mapstructure:"maven-url"`
	MaxParentRecursiveDepth       int    `yaml:"max-parent-recursive-depth" json:"max-parent-recursive-depth" mapstructure:"max-parent-recursive-depth"`
	ResolveTransitiveDependencies bool   `yaml:"resolve-transitive-dependencies" json:"resolve-transitive-dependencies" mapstructure:"resolve-transitive-dependencies"`
}

func defaultJavaConfig() javaConfig {
	def := java.DefaultArchiveCatalogerConfig()

	return javaConfig{
		UseNetwork:                    nil, // this defaults to false, which is the API default
		MaxParentRecursiveDepth:       def.MaxParentRecursiveDepth,
		UseMavenLocalRepository:       nil, // this defaults to false, which is the API default
		MavenLocalRepositoryDir:       def.MavenLocalRepositoryDir,
		MavenURL:                      def.MavenBaseURL,
		ResolveTransitiveDependencies: def.ResolveTransitiveDependencies,
	}
}

var _ interface {
	clio.FieldDescriber
} = (*javaConfig)(nil)

func (o *javaConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.UseNetwork, `enables Syft to use the network to fetch version and license information for packages when
a parent or imported pom file is not found in the local maven repository.
the pom files are downloaded from the remote Maven repository at 'maven-url'`)
	descriptions.Add(&o.MavenURL, `maven repository to use, defaults to Maven central`)
	descriptions.Add(&o.MaxParentRecursiveDepth, `depth to recursively resolve parent POMs, no limit if <= 0`)
	descriptions.Add(&o.UseMavenLocalRepository, `use the local Maven repository to retrieve pom files. When Maven is installed and was previously used
for building the software that is being scanned, then most pom files will be available in this
repository on the local file system. this greatly speeds up scans. when all pom files are available
in the local repository, then 'use-network' is not needed.
TIP: If you want to download all required pom files to the local repository without running a full
build, run 'mvn help:effective-pom' before performing the scan with syft.`)
	descriptions.Add(&o.MavenLocalRepositoryDir, `override the default location of the local Maven repository. 
the default is the subdirectory '.m2/repository' in your home directory`)
	descriptions.Add(&o.ResolveTransitiveDependencies, `resolve transient dependencies such as those defined in a dependency's POM on Maven central`)
}
