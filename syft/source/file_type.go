package source

import (
	"archive/tar"
	"os"
)

const (
	RegularFile FileType = "RegularFile"
	// IrregularFile is how syft defines files that are neither regular, symbolic or directory.
	// For ref: the seven standard Unix file types are regular, directory, symbolic link,
	// FIFO special, block special, character special, and socket as defined by POSIX.
	IrregularFile   FileType = "IrregularFile"
	HardLink        FileType = "HardLink"
	SymbolicLink    FileType = "SymbolicLink"
	CharacterDevice FileType = "CharacterDevice"
	BlockDevice     FileType = "BlockDevice"
	Directory       FileType = "Directory"
	FIFONode        FileType = "FIFONode"
	Socket          FileType = "Socket"
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
	return IrregularFile
}

func newFileTypeFromMode(mode os.FileMode) FileType {
	switch {
	case isSet(mode, os.ModeSymlink):
		return SymbolicLink
	case isSet(mode, os.ModeIrregular):
		return IrregularFile
	case isSet(mode, os.ModeCharDevice):
		return CharacterDevice
	case isSet(mode, os.ModeDevice):
		return BlockDevice
	case isSet(mode, os.ModeNamedPipe):
		return FIFONode
	case isSet(mode, os.ModeSocket):
		return Socket
	case mode.IsDir():
		return Directory
	case mode.IsRegular():
		return RegularFile
	default:
		return IrregularFile
	}
}

func isSet(mode, field os.FileMode) bool {
	return mode&field != 0
}
