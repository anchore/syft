package distro

import (
	"fmt"

	hashiVer "github.com/hashicorp/go-version"
)

type Distro struct {
	Type       Type
	Version    *hashiVer.Version
	RawVersion string
	IDLike     string
}

// NewUnknownDistro creates a standardized Distro object for unidentifiable distros
func NewUnknownDistro() Distro {
	return Distro{
		Type: UnknownDistroType,
	}
}

func NewDistro(t Type, ver, like string) (Distro, error) {
	if ver == "" {
		return Distro{Type: t}, nil
	}
	verObj, err := hashiVer.NewVersion(ver)
	if err != nil {
		return Distro{}, fmt.Errorf("could not create distro version: %w", err)
	}
	return Distro{
		Type:       t,
		Version:    verObj,
		RawVersion: ver,
		IDLike:     like,
	}, nil
}

func (d Distro) MajorVersion() string {
	if d.Version == nil {
		return fmt.Sprint("(version unknown)")
	}
	return fmt.Sprintf("%d", d.Version.Segments()[0])
}

func (d Distro) FullVersion() string {
	return d.RawVersion
}

func (d Distro) String() string {
	versionStr := "(version unknown)"
	if d.RawVersion != "" {
		versionStr = d.RawVersion
	}
	return fmt.Sprintf("%s %s", d.Type, versionStr)
}

// Name provides a string repr of the distro
func (d Distro) Name() string {
	return string(d.Type)
}
