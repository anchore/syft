package pkg

// LinuxKernelMetadata represents all captured data for a Linux kernel
type LinuxKernelMetadata struct {
	Name            string `mapstructure:"name" json:"name" cyclonedx:"name"`
	Architecture    string `mapstructure:"architecture" json:"architecture" cyclonedx:"architecture"`
	Version         string `mapstructure:"version" json:"version" cyclonedx:"version"`
	ExtendedVersion string `mapstructure:"extendedVersion" json:"extendedVersion,omitempty" cyclonedx:"extendedVersion"`
	BuildTime       string `mapstructure:"buildTime" json:"buildTime,omitempty" cyclonedx:"buildTime"`
	Author          string `mapstructure:"author" json:"author,omitempty" cyclonedx:"author"`
	Format          string `mapstructure:"format" json:"format,omitempty" cyclonedx:"format"`
	RWRootFS        bool   `mapstructure:"rwRootFS" json:"rwRootFS,omitempty" cyclonedx:"rwRootFS"`
	SwapDevice      int    `mapstructure:"swapDevice" json:"swapDevice,omitempty" cyclonedx:"swapDevice"`
	RootDevice      int    `mapstructure:"rootDevice" json:"rootDevice,omitempty" cyclonedx:"rootDevice"`
	VideoMode       string `mapstructure:"videoMode" json:"videoMode,omitempty" cyclonedx:"videoMode"`
}

type LinuxKernelModuleMetadata struct {
	Name          string                                `mapstructure:"name" json:"name,omitempty" cyclonedx:"name"`
	Version       string                                `mapstructure:"version" json:"version,omitempty" cyclonedx:"version"`
	SourceVersion string                                `mapstructure:"sourceVersion" json:"sourceVersion,omitempty" cyclonedx:"sourceVersion"`
	Path          string                                `mapstructure:"path" json:"path,omitempty" cyclonedx:"path"`
	Description   string                                `mapstructure:"description" json:"description,omitempty" cyclonedx:"description"`
	Author        string                                `mapstructure:"author" json:"author,omitempty" cyclonedx:"author"`
	License       string                                `mapstructure:"license" json:"license,omitempty" cyclonedx:"license"`
	KernelVersion string                                `mapstructure:"kernelVersion" json:"kernelVersion,omitempty" cyclonedx:"kernelVersion"`
	VersionMagic  string                                `mapstructure:"versionMagic" json:"versionMagic,omitempty" cyclonedx:"versionMagic"`
	Parameters    map[string]LinuxKernelModuleParameter `mapstructure:"parameters" json:"parameters,omitempty" cyclonedx:"parameters"`
}

type LinuxKernelModuleParameter struct {
	Type        string `mapstructure:"type" json:"type,omitempty" cyclonedx:"type"`
	Description string `mapstructure:"description" json:"description,omitempty" cyclonedx:"description"`
}
