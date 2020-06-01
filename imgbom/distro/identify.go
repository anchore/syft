package distro

import (
	"github.com/anchore/stereoscope/pkg/image"
)

func Identify(img *image.Image) (Distro, error) {
	// TODO: implement me based off of https://github.com/anchore/anchore-engine/blob/78b23d7e8f007005c070673405b5e23730a660e0/anchore_engine/analyzers/utils.py#L131

	return NewDistro(UnknownDistro, "0.0.0")
}
