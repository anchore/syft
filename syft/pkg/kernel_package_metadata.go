package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

// KernelPackageMetadata represents all captured data for a Linux kernel
type KernelPackageMetadata struct {
	Name            string                 `mapstructure:"name" json:"name" cyclonedx:"name"`
	Architecture    string                 `mapstructure:"architecture" json:"architecture" cyclonedx:"architecture"`
	Version         string                 `mapstructure:"version" json:"version" cyclonedx:"version"`
	ExtendedVersion string                 `mapstructure:"extendedVersion" json:"extendedVersion,omitempty" cyclonedx:"extendedVersion"`
	BuildTime       string                 `mapstructure:"buildTime" json:"buildTime,omitempty" cyclonedx:"buildTime"`
	Author          string                 `mapstructure:"author" json:"author,omitempty" cyclonedx:"author"`
	Format          string                 `mapstructure:"format" json:"format,omitempty" cyclonedx:"format"`
	RWRootFS        bool                   `mapstructure:"rwRootFS" json:"rwRootFS,omitempty" cyclonedx:"rwRootFS"`
	SwapDevice      int                    `mapstructure:"swapDevice" json:"swapDevice,omitempty" cyclonedx:"swapDevice"`
	RootDevice      int                    `mapstructure:"rootDevice" json:"rootDevice,omitempty" cyclonedx:"rootDevice"`
	VideoMode       string                 `mapstructure:"videoMode" json:"videoMode,omitempty" cyclonedx:"videoMode"`
	Modules         []KernelModuleMetadata `mapstructure:"modules" json:"modules" cyclonedx:"modules"`
}

func (m KernelPackageMetadata) OwnedFiles() (result []string) {
	s := strset.New()
	for _, m := range m.Modules {
		if m.Path != "" {
			s.Add(m.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return
}

type KernelModuleMetadata struct {
	KernelVersion string                           `mapstructure:"kernelVersion" json:"kernelVersion,omitempty" cyclonedx:"kernelVersion"`
	VersionMagic  string                           `mapstructure:"versionMagic" json:"versionMagic,omitempty" cyclonedx:"versionMagic"`
	SourceVersion string                           `mapstructure:"sourceVersion" json:"sourceVersion,omitempty" cyclonedx:"sourceVersion"`
	Version       string                           `mapstructure:"version" json:"version,omitempty" cyclonedx:"version"`
	Author        string                           `mapstructure:"author" json:"author,omitempty" cyclonedx:"author"`
	License       string                           `mapstructure:"license" json:"license,omitempty" cyclonedx:"license"`
	Name          string                           `mapstructure:"name" json:"name,omitempty" cyclonedx:"name"`
	Description   string                           `mapstructure:"description" json:"description,omitempty" cyclonedx:"description"`
	Path          string                           `mapstructure:"path" json:"path,omitempty" cyclonedx:"path"`
	Parameters    map[string]KernelModuleParameter `mapstructure:"parameters" json:"parameters,omitempty" cyclonedx:"parameters"`
}

type KernelModuleParameter struct {
	Description string `mapstructure:"description" json:"description,omitempty" cyclonedx:"description"`
	Type        string `mapstructure:"type" json:"type,omitempty" cyclonedx:"type"`
}
