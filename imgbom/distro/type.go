package distro

const (
	UnknownDistroType Type = iota
	Debian
	Ubuntu
	RedHat
	CentOS
	// Fedora
	// Alpine
	Busybox
	// AmazonLinux
	// OracleLinux
	// ArchLinux
)

const (
	// UnknownVersion is a default of 0.0.0 when it can't be parsed
	UnknownVersion string = "0.0.0"
)

type Type int

var distroStr = []string{
	"UnknownDistroType",
	"debian",
	"ubuntu",
	"redhat",
	"centos",
	// "fedora",
	// "alpine",
	"busybox",
	// "amazn",
	// "oraclelinux",
	// "archlinux",
}

var All = []Type{
	Debian,
	Ubuntu,
	RedHat,
	CentOS,
	// Fedora,
	// Alpine,
	Busybox,
	// AmazonLinux,
	// OracleLinux,
	// ArchLinux,
}

func (t Type) String() string {
	if int(t) >= len(distroStr) || t < 0 {
		return distroStr[0]
	}

	return distroStr[t]
}

// Mappings connects a distro ID like "ubuntu" to a Distro type
var Mappings = map[string]Type{
	"debian": Debian,
	"ubuntu": Ubuntu,
	"rhel":   RedHat,
	"centos": CentOS,
	// "fedora": Fedora,
	// "alpine": Alpine,
	"busybox": Busybox,
	// "amazn": AmazonLinux,
	// "oraclelinux": OracleLinux,
	// "archlinux": ArchLinux,
}
