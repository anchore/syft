package distro

const (
	UnknownDistroType Type = iota
	Debian
	Ubuntu
	RedHat
	CentOS
	Fedora
	Alpine
	Busybox
	AmazonLinux
	OracleLinux
	ArchLinux
	OpenSuseLeap
)

type Type int

var distroStr = []string{
	"UnknownDistroType",
	"debian",
	"ubuntu",
	"redhat",
	"centos",
	"fedora",
	"alpine",
	"busybox",
	"amazn",
	"oraclelinux",
	"archlinux",
	"opensuse-leap",
}

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

func (t Type) String() string {
	if int(t) >= len(distroStr) || t < 0 {
		return distroStr[0]
	}

	return distroStr[t]
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
