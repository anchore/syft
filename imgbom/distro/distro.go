package distro

import (
	"fmt"

	hashiVer "github.com/hashicorp/go-version"
)

type Distro struct {
	Type       Type
	Version    *hashiVer.Version
	RawVersion string
}

func NewDistro(t Type, ver string) (Distro, error) {
	verObj, err := hashiVer.NewVersion(ver)
	if err != nil {
		return Distro{}, fmt.Errorf("could not create distro version: %w", err)
	}
	return Distro{
		Type:       t,
		Version:    verObj,
		RawVersion: ver,
	}, nil
}

func (d Distro) MajorVersion() string {
	return fmt.Sprintf("%d", d.Version.Segments()[0])
}

func (d Distro) FullVersion() string {
	return d.RawVersion
}

func (d Distro) String() string {
	return fmt.Sprintf("%s %s", d.Type, d.RawVersion)
}

// Name provides a string repr of the distro
func (d Distro) Name() string {
	return fmt.Sprintf("%s", d.Type)
}
