package pkg

// KernelPackageMetadata represents all captured data for a Linux kernel
type KernelPackageMetadata struct {
	Name            string                 `mapstructure:"name" json:"name"`
	Architecture    string                 `mapstructure:"architecture" json:"architecture"`
	Version         string                 `mapstructure:"version" json:"version"`
	ExtendedVersion string                 `mapstructure:"extendedVersion" json:"extendedVersion,omitempty"`
	BuildTime       string                 `mapstructure:"buildTime" json:"buildTime,omitempty"`
	Author          string                 `mapstructure:"author" json:"author,omitempty"`
	Format          string                 `mapstructure:"format" json:"format,omitempty"`
	RWRootFS        bool                   `mapstructure:"rwRootFS" json:"rwRootFS,omitempty"`
	SwapDevice      int                    `mapstructure:"swapDevice" json:"swapDevice,omitempty"`
	RootDevice      int                    `mapstructure:"rootDevice" json:"rootDevice,omitempty"`
	VideoMode       string                 `mapstructure:"videoMode" json:"videoMode,omitempty"`
	Modules         []KernelModuleMetadata `mapstructure:"modules" json:"modules"`
}

type KernelModuleMetadata struct {
	KernelVersion string                           `mapstructure:"kernelVersion" json:"kernelVersion,omitempty"`
	VersionMagic  string                           `mapstructure:"versionMagic" json:"versionMagic,omitempty"`
	SourceVersion string                           `mapstructure:"sourceVersion" json:"sourceVersion,omitempty"`
	Version       string                           `mapstructure:"version" json:"version,omitempty"`
	Author        string                           `mapstructure:"author" json:"author,omitempty"`
	License       string                           `mapstructure:"license" json:"license,omitempty"`
	Name          string                           `mapstructure:"name" json:"name,omitempty"`
	Description   string                           `mapstructure:"description" json:"description,omitempty"`
	Path          string                           `mapstructure:"path" json:"path,omitempty"`
	Parameters    map[string]KernelModuleParameter `mapstructure:"parameters" json:"parameters,omitempty"`
}

type KernelModuleParameter struct {
	Description string `mapstructure:"description" json:"description,omitempty"`
	Type        string `mapstructure:"type" json:"type,omitempty"`
}
