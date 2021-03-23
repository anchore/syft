package source

const (
	UnknownFileType FileType = "unknownFileType"
	RegularFile     FileType = "regularFile"
	HardLink        FileType = "hardLink"
	SymbolicLink    FileType = "symbolicLink"
	CharacterDevice FileType = "characterDevice"
	BlockDevice     FileType = "blockDevice"
	Directory       FileType = "directory"
	FIFONode        FileType = "fifoNode"
)

type FileType string

func newFileTypeFromTarHeaderTypeFlag(flag byte) FileType {
	switch flag {
	case '0', '\x00':
		return RegularFile
	case '1':
		return HardLink
	case '2':
		return SymbolicLink
	case '3':
		return CharacterDevice
	case '4':
		return BlockDevice
	case '5':
		return Directory
	case '6':
		return FIFONode
	}
	return UnknownFileType
}
