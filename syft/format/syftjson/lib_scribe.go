package syftjson

import (
	"github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/source"
)

func ToSourceModel(src source.Description) model.Source {
	return toSourceModel(src)
}
