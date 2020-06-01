package distro

const (
	UnknownDistro Type = iota
	Debian
	// Ubuntu
	// RedHat
	// CentOS
	// Fedora
	// Alpine
	// Busybox
	// AmazonLinux
	// OracleLinux
	// ArchLinux
)

type Type int

var distroStr = []string{
	"UnknownDistro",
	"Debian",
	// "Ubuntu",
	// "RedHat",
	// "CentOS",
	// "Fedora",
	// "Alpine",
	// "Busybox",
	// "AmazonLinux",
	// "OracleLinux",
	// "ArchLinux",
}

var All = []Type{
	Debian,
	// Ubuntu,
	// RedHat,
	// CentOS,
	// Fedora,
	// Alpine,
	// Busybox,
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
