package pkgcataloging

import (
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
)

type Config struct {
	Binary      binary.ClassifierCatalogerConfig  `yaml:"binary" json:"binary" mapstructure:"binary"`
	Golang      golang.CatalogerConfig            `yaml:"golang" json:"golang" mapstructure:"golang"`
	JavaArchive java.ArchiveCatalogerConfig       `yaml:"java-archive" json:"java-archive" mapstructure:"java-archive"`
	JavaScript  javascript.CatalogerConfig        `yaml:"javascript" json:"javascript" mapstructure:"javascript"`
	LinuxKernel kernel.LinuxKernelCatalogerConfig `yaml:"linux-kernel" json:"linux-kernel" mapstructure:"linux-kernel"`
	Python      python.CatalogerConfig            `yaml:"python" json:"python" mapstructure:"python"`
}

func DefaultConfig() Config {
	return Config{
		Binary:      binary.DefaultClassifierCatalogerConfig(),
		Golang:      golang.DefaultCatalogerConfig(),
		LinuxKernel: kernel.DefaultLinuxKernelCatalogerConfig(),
		Python:      python.DefaultCatalogerConfig(),
		JavaArchive: java.DefaultArchiveCatalogerConfig(),
	}
}

func (c Config) WithBinaryConfig(cfg binary.ClassifierCatalogerConfig) Config {
	c.Binary = cfg
	return c
}

func (c Config) WithGolangConfig(cfg golang.CatalogerConfig) Config {
	c.Golang = cfg
	return c
}

func (c Config) WithJavascriptConfig(cfg javascript.CatalogerConfig) Config {
	c.JavaScript = cfg
	return c
}

func (c Config) WithLinuxKernelConfig(cfg kernel.LinuxKernelCatalogerConfig) Config {
	c.LinuxKernel = cfg
	return c
}

func (c Config) WithPythonConfig(cfg python.CatalogerConfig) Config {
	c.Python = cfg
	return c
}

func (c Config) WithJavaArchiveConfig(cfg java.ArchiveCatalogerConfig) Config {
	c.JavaArchive = cfg
	return c
}
