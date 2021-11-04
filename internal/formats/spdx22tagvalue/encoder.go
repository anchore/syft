package spdx22tagvalue

import (
	"io"

	"github.com/spdx/tools-golang/tvsaver"

	"github.com/anchore/syft/syft/distro"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func encoder(output io.Writer, catalog *pkg.Catalog, srcMetadata *source.Metadata, d *distro.Distro, scope source.Scope) error {
	model := toFormatModel(catalog, srcMetadata, d, scope)
	return tvsaver.Save2_2(&model, output)
}
