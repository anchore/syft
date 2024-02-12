package executable

import (
	"debug/pe"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

func findPEFeatures(data *file.Executable, reader unionreader.UnionReader) error {
	// TODO: support security features

	f, err := pe.NewFile(reader)
	if err != nil {
		return err
	}

	libs, err := f.ImportedLibraries()
	if err != nil {
		return err
	}

	data.ImportedLibraries = libs
	data.HasEntrypoint = peHasEntrypoint(f)
	data.HasExports = peHasExports(f)

	return nil
}

func peHasEntrypoint(f *pe.File) bool {
	switch v := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return v.AddressOfEntryPoint > 0
	case *pe.OptionalHeader64:
		return v.AddressOfEntryPoint > 0
	}
	return false
}

func peHasExports(f *pe.File) bool {
	if f.OptionalHeader == nil {
		return false
	}

	switch v := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return v.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0
	case *pe.OptionalHeader64:
		return v.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0
	}

	return false
}
