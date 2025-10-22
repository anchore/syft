package pkg

// LinuxKernel represents all captured data for a Linux kernel
type LinuxKernel struct {
	// Name is kernel name (typically "Linux")
	Name string `mapstructure:"name" json:"name" cyclonedx:"name"`

	// Architecture is the target CPU architecture
	Architecture string `mapstructure:"architecture" json:"architecture" cyclonedx:"architecture"`

	// Version is kernel version string
	Version string `mapstructure:"version" json:"version" cyclonedx:"version"`

	// ExtendedVersion is additional version information
	ExtendedVersion string `mapstructure:"extendedVersion" json:"extendedVersion,omitempty" cyclonedx:"extendedVersion"`

	// BuildTime is when the kernel was built
	BuildTime string `mapstructure:"buildTime" json:"buildTime,omitempty" cyclonedx:"buildTime"`

	// Author is who built the kernel
	Author string `mapstructure:"author" json:"author,omitempty" cyclonedx:"author"`

	// Format is kernel image format (e.g. bzImage, zImage)
	Format string `mapstructure:"format" json:"format,omitempty" cyclonedx:"format"`

	// RWRootFS is whether root filesystem is mounted read-write
	RWRootFS bool `mapstructure:"rwRootFS" json:"rwRootFS,omitempty" cyclonedx:"rwRootFS"`

	// SwapDevice is swap device number
	SwapDevice int `mapstructure:"swapDevice" json:"swapDevice,omitempty" cyclonedx:"swapDevice"`

	// RootDevice is root device number
	RootDevice int `mapstructure:"rootDevice" json:"rootDevice,omitempty" cyclonedx:"rootDevice"`

	// VideoMode is default video mode setting
	VideoMode string `mapstructure:"videoMode" json:"videoMode,omitempty" cyclonedx:"videoMode"`
}

// LinuxKernelModule represents a loadable kernel module (.ko file) with its metadata, parameters, and dependencies.
type LinuxKernelModule struct {
	// Name is module name
	Name string `mapstructure:"name" json:"name,omitempty" cyclonedx:"name"`

	// Version is module version string
	Version string `mapstructure:"version" json:"version,omitempty" cyclonedx:"version"`

	// SourceVersion is the source code version identifier
	SourceVersion string `mapstructure:"sourceVersion" json:"sourceVersion,omitempty" cyclonedx:"sourceVersion"`

	// Path is the filesystem path to the .ko kernel object file (absolute path)
	Path string `mapstructure:"path" json:"path,omitempty" cyclonedx:"path"`

	// Description is a human-readable module description
	Description string `mapstructure:"description" json:"description,omitempty" cyclonedx:"description"`

	// Author is module author name and email
	Author string `mapstructure:"author" json:"author,omitempty" cyclonedx:"author"`

	// License is module license (e.g. GPL, BSD) which must be compatible with kernel
	License string `mapstructure:"license" json:"license,omitempty" cyclonedx:"license"`

	// KernelVersion is kernel version this module was built for
	KernelVersion string `mapstructure:"kernelVersion" json:"kernelVersion,omitempty" cyclonedx:"kernelVersion"`

	// VersionMagic is version magic string for compatibility checking (includes kernel version, SMP status, module loading capabilities like "3.17.4-302.fc21.x86_64 SMP mod_unload modversions"). Module will NOT load if vermagic doesn't match running kernel.
	VersionMagic string `mapstructure:"versionMagic" json:"versionMagic,omitempty" cyclonedx:"versionMagic"`

	// Parameters are the module parameters that can be configured at load time (user-settable values like module options)
	Parameters map[string]LinuxKernelModuleParameter `mapstructure:"parameters" json:"parameters,omitempty" cyclonedx:"parameters"`
}

// LinuxKernelModuleParameter represents a configurable parameter for a kernel module with its type and description.
type LinuxKernelModuleParameter struct {
	// Type is parameter data type (e.g. int, string, bool, array types)
	Type string `mapstructure:"type" json:"type,omitempty" cyclonedx:"type"`

	// Description is a human-readable parameter description explaining what the parameter controls
	Description string `mapstructure:"description" json:"description,omitempty" cyclonedx:"description"`
}
