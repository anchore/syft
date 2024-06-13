package pkg

import "github.com/anchore/syft/syft/sort"

// LinuxKernel represents all captured data for a Linux kernel
type LinuxKernel struct {
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

type LinuxKernelModule struct {
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

func (m LinuxKernel) Compare(other LinuxKernel) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Architecture, other.Architecture); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.ExtendedVersion, other.ExtendedVersion); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.BuildTime, other.BuildTime); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Author, other.Author); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Format, other.Format); i != 0 {
		return i
	}
	if i := sort.CompareBool(m.RWRootFS, other.RWRootFS); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.SwapDevice, other.SwapDevice); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.RootDevice, other.RootDevice); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.VideoMode, other.VideoMode); i != 0 {
		return i
	}
	return 0
}
func (m LinuxKernelModule) Compare(other LinuxKernelModule) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.SourceVersion, other.SourceVersion); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Description, other.Description); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Author, other.Author); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.License, other.License); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.KernelVersion, other.KernelVersion); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.VersionMagic, other.VersionMagic); i != 0 {
		return i
	}
	if i := sort.CompareMap(m.Parameters, other.Parameters); i != 0 {
		return i
	}
	return 0
}
func (m LinuxKernelModuleParameter) Compare(other LinuxKernelModuleParameter) int {
	if i := sort.CompareOrd(m.Type, other.Type); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Description, other.Description); i != 0 {
		return i
	}
	return 0
}

func (m LinuxKernel) TryCompare(other any) (bool, int) {
	if other, exists := other.(LinuxKernel); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
func (m LinuxKernelModule) TryCompare(other any) (bool, int) {
	if other, exists := other.(LinuxKernelModule); exists {
		return true, m.Compare(other)
	}
	return false, 0
}

func (m LinuxKernelModuleParameter) TryCompare(other any) (bool, int) {
	if other, exists := other.(LinuxKernelModuleParameter); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
