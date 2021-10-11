package format

import (
	"io"

	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// TODO: this should probably be a helper function to return the bytes
//func using() {
//	var buff bytes.Buffer
//	var encoder Encoder // = ...
//
//	_:=encoder(&buff, nil, nil, nil)
//
//	bytes.NewReader(buff.Bytes())
//
//}

type Encoder func(io.Writer, *pkg.Catalog, *source.Metadata, *distro.Distro) error
