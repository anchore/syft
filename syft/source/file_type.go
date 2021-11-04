package source

import (
	"archive/tar"
	"os"
)

const (
	UnknownFileType FileType = "UnknownFileType"
	RegularFile     FileType = "RegularFile"
	IrregularFile   FileType = "IrregularFile"
	HardLink        FileType = "HardLink"
	SymbolicLink    FileType = "SymbolicLink"
	CharacterDevice FileType = "CharacterDevice"
	BlockDevice     FileType = "BlockDevice"
	Directory       FileType = "Directory"
	FIFONode        FileType = "FIFONode"
)

type FileType string

func newFileTypeFromTarHeaderTypeFlag(flag byte) FileType {
	switch flag {
	case tar.TypeReg, tar.TypeRegA:
		return RegularFile
	case tar.TypeLink:
		return HardLink
	case tar.TypeSymlink:
		return SymbolicLink
	case tar.TypeChar:
		return CharacterDevice
	case tar.TypeBlock:
		return BlockDevice
	case tar.TypeDir:
		return Directory
	case tar.TypeFifo:
		return FIFONode
	}
	return UnknownFileType
}

// TODO: fill in more types from mod...
func newFileTypeFromMode(mode os.FileMode) FileType {
	switch {
	case mode&os.ModeSymlink == os.ModeSymlink:
		return SymbolicLink
	case mode.IsDir():
		return Directory
	case !mode.IsRegular():
		return IrregularFile
	default:
		return RegularFile
	}
}
