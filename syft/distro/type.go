package distro

type Type string

const (
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
)

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
}

func (t Type) String() string {
	return string(t)
}
