package internal

import "github.com/anchore/stereoscope/pkg/file"

var RootTempDirGenerator = file.NewTempDirGenerator(ApplicationName)
