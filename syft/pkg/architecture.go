package pkg

// Architecture is the interface that wraps the TargetArchitecture method.
//
// TargetArchitecture returns the target CPU architecture a piece of package Metadata records,
// in its ecosystem's native spelling: rpm and apk use the GNU/kernel form ("x86_64",
// "aarch64", "noarch"), while dpkg uses the Debian form ("amd64", "arm64", "all"). It lets
// consumers read a package's architecture directly from metadata rather than parsing the
// PURL "arch" qualifier.
//
// The method is named TargetArchitecture rather than Architecture (or Arch) because the dpkg
// and apk metadata already expose an Architecture field, and rpm an Arch field; Go does not
// permit a method to share a name with a field on the same type.
type Architecture interface {
	TargetArchitecture() string
}
