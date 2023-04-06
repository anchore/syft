/*
Package kernel provides a concrete Cataloger implementation for linux kernel and module files.
*/
package kernel

import (
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type CatalogerOpts struct {
	KernelFilenameAppends       []string
	KernelModuleFilenameAppends []string
}

var kernelFiles = []string{
	"kernel",
	"kernel-*",
	"vmlinux",
	"vmlinux-*",
	"vmlinuz",
	"vmlinuz-*",
}

// NewLinuxKernelCataloger returns a new kernel files cataloger object.
func NewLinuxKernelCataloger(opts CatalogerOpts) *generic.Cataloger {
	var fileList []string
	for _, file := range kernelFiles {
		fileList = append(fileList, "**/"+file)
	}
	for _, file := range opts.KernelFilenameAppends {
		fileList = append(fileList, "**/"+file)
	}
	return generic.NewCataloger("linux-kernel-cataloger").
		WithParserByGlobs(parseLinuxKernelFile, fileList...)
}
