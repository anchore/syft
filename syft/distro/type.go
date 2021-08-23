package distro

// Type represents the different Linux distribution options
type Type string

const (
	// represents the set of valid/supported Linux Distributions
	UnknownDistroType Type = "UnknownDistroType"
	Debian            Type = "debian"
	Ubuntu            Type = "ubuntu"
	RedHat            Type = "redhat"
	CentOS            Type = "centos"
	Fedora            Type = "fedora"
	Alpine            Type = "alpine"
	Busybox           Type = "busybox"
	AmazonLinux       Type = "amazonlinux"
	OracleLinux       Type = "oraclelinux"
	ArchLinux         Type = "archlinux"
	OpenSuseLeap      Type = "opensuseleap"
	SLES              Type = "sles"
	Photon            Type = "photon"
	Windows           Type = "windows"
)

// All contains all Linux distribution options
var All = []Type{
	Debian,
	Ubuntu,
	RedHat,
	CentOS,
	Fedora,
	Alpine,
	Busybox,
	AmazonLinux,
	OracleLinux,
	ArchLinux,
	OpenSuseLeap,
	SLES,
	Photon,
	Windows,
}

// IDMapping connects a distro ID like "ubuntu" to a Distro type
var IDMapping = map[string]Type{
	"debian":        Debian,
	"ubuntu":        Ubuntu,
	"rhel":          RedHat,
	"centos":        CentOS,
	"fedora":        Fedora,
	"alpine":        Alpine,
	"busybox":       Busybox,
	"amzn":          AmazonLinux,
	"ol":            OracleLinux,
	"arch":          ArchLinux,
	"opensuse-leap": OpenSuseLeap,
	"sles":          SLES,
	"photon":        Photon,
	"windows":       Windows,
}

// String returns the string representation of the given Linux distribution.
func (t Type) String() string {
	return string(t)
}
