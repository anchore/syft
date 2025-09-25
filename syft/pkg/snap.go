package pkg

const (
	SnapTypeBase   = "base"
	SnapTypeKernel = "kernel"
	SnapTypeApp    = "app"
	SnapTypeGadget = "gadget"
	SnapTypeSnapd  = "snapd"
)

type SnapEntry struct {
	SnapType     string `json:"snapType" yaml:"snapType"`         // base, kernel, system, gadget, snapd
	Base         string `json:"base" yaml:"base"`                 // base snap name (e.g., core20, core22)
	SnapName     string `json:"snapName" yaml:"snapName"`         // name of the snap
	SnapVersion  string `json:"snapVersion" yaml:"snapVersion"`   // version of the snap
	Architecture string `json:"architecture" yaml:"architecture"` // architecture (amd64, arm64, etc.)

}
