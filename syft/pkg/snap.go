package pkg

const (
	SnapTypeBase   = "base"
	SnapTypeKernel = "kernel"
	SnapTypeApp    = "app"
	SnapTypeGadget = "gadget"
	SnapTypeSnapd  = "snapd"
)

// SnapEntry represents metadata for a Snap package extracted from snap.yaml or snapcraft.yaml files.
type SnapEntry struct {
	// SnapType indicates the snap type (base, kernel, app, gadget, or snapd).
	SnapType string `json:"snapType" yaml:"snapType"` // base, kernel, system, gadget, snapd

	// Base is the base snap name that this snap depends on (e.g., "core20", "core22").
	Base string `json:"base" yaml:"base"` // base snap name (e.g., core20, core22)

	// SnapName is the snap package name.
	SnapName string `json:"snapName" yaml:"snapName"` // name of the snap

	// SnapVersion is the snap package version.
	SnapVersion string `json:"snapVersion" yaml:"snapVersion"` // version of the snap

	// Architecture is the target CPU architecture (e.g., "amd64", "arm64").
	Architecture string `json:"architecture" yaml:"architecture"` // architecture (amd64, arm64, etc.)

}
