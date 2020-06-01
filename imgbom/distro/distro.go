package distro

import (
	"fmt"

	hashiVer "github.com/hashicorp/go-version"
)

type Distro struct {
	Type    Type
	Version *hashiVer.Version
}

func NewDistro(t Type, ver string) (Distro, error) {
	verObj, err := hashiVer.NewVersion(ver)
	if err != nil {
		return Distro{}, fmt.Errorf("could not create distro version: %w", err)
	}
	return Distro{
		Type:    t,
		Version: verObj,
	}, nil
}

func (d Distro) MajorVersion() int {
	return d.Version.Segments()[0]
}

func (d Distro) String() string {
	return fmt.Sprintf("%s %s", d.Type, d.Version)
}
