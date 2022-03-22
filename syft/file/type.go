package file

import (
	"archive/tar"
	"os"
)

const (
	RegularFile Type = "RegularFile"
	// IrregularFile is how syft defines files that are neither regular, symbolic or directory.
	// For ref: the seven standard Unix file types are regular, directory, symbolic link,
	// FIFO special, block special, character special, and socket as defined by POSIX.
	IrregularFile   Type = "IrregularFile"
	HardLink        Type = "HardLink"
	SymbolicLink    Type = "SymbolicLink"
	CharacterDevice Type = "CharacterDevice"
	BlockDevice     Type = "BlockDevice"
	Directory       Type = "Directory"
	FIFONode        Type = "FIFONode"
	Socket          Type = "Socket"
)

type Type string

func NewFileTypeFromTarHeaderTypeFlag(flag byte) Type {
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

func NewFileTypeFromMode(mode os.FileMode) Type {
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
