package pkg

// KernelPackageMetadata represents all captured data for a Linux kernel
type KernelPackageMetadata struct {
	Name            string `mapstructure:"name" json:"name"`
	Architecture    string `mapstructure:"architecture" json:"architecture"`
	Version         string `mapstructure:"version" json:"version"`
	ExtendedVersion string `mapstructure:"extendedVersion" json:"extendedVersion,omitempty"`
	BuildTime       string `mapstructure:"buildTime" json:"buildTime,omitempty"`
	Author          string `mapstructure:"author" json:"author,omitempty"`
	Format          string `mapstructure:"format" json:"format,omitempty"`
	RWRootFS        bool   `mapstructure:"rwRootFS" json:"rwRootFS,omitempty"`
	SwapDevice      int    `mapstructure:"swapDevice" json:"swapDevice,omitempty"`
	RootDevice      int    `mapstructure:"rootDevice" json:"rootDevice,omitempty"`
	VideoMode       string `mapstructure:"videoMode" json:"videoMode,omitempty"`
}
