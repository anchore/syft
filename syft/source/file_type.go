package source

import "archive/tar"

const (
	UnknownFileType FileType = "UnknownFileType"
	RegularFile     FileType = "RegularFile"
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
