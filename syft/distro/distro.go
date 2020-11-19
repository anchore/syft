package distro

import (
	"fmt"

	hashiVer "github.com/hashicorp/go-version"
)

// Distro represents a Linux Distribution.
type Distro struct {
	Type       Type
	Version    *hashiVer.Version
	RawVersion string
	IDLike     string
}

// NewDistro creates a new Distro object populated with the given values.
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

// Name provides a string repr of the distro
func (d Distro) Name() string {
	return string(d.Type)
}

// MajorVersion returns the major version value from the pseudo-semantically versioned distro version value.
func (d Distro) MajorVersion() string {
	if d.Version == nil {
		return fmt.Sprint("(version unknown)")
	}
	return fmt.Sprintf("%d", d.Version.Segments()[0])
}

// FullVersion returns the original user version value.
func (d Distro) FullVersion() string {
	return d.RawVersion
}

// String returns a human-friendly representation of the Linux distribution.
func (d Distro) String() string {
	versionStr := "(version unknown)"
	if d.RawVersion != "" {
		versionStr = d.RawVersion
	}
	return fmt.Sprintf("%s %s", d.Type, versionStr)
}
