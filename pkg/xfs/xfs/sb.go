package xfs

type SuperBlock struct {
	Magicnum   uint32
	BlockSize  uint32
	Dblocks    uint64
	Rblocks    uint64
	Rextens    uint64
	UUID       [16]byte
	Logstart   uint64
	Rootino    uint64
	Rbmino     uint64
	Rsmino     uint64
	Rextsize   uint32
	Agblocks   uint32
	Agcount    uint32
	Rbblocks   uint32
	Logblocks  uint32
	Versionnum uint16
	Sectsize   uint16
	Inodesize  uint16
	Inopblock  uint16
	Fname      [12]byte
	Blocklog   uint8
	Sectlog    uint8
	Inodelog   uint8
	Inopblog   uint8
	Agblklog   uint8
	Rextslog   uint8
	Inprogress uint8
	ImaxPct    uint8

	Icount    uint64
	Ifree     uint64
	Fdblocks  uint64
	Frextents uint64

	Uqunotino   uint64
	Gquotino    uint64
	Qflags      uint16
	Flags       uint8
	SharedVn    uint8
	Inoalignmt  uint32
	Unit        uint32
	Width       uint32
	Dirblklog   uint8
	Logsectlog  uint8
	Logsectsize uint16
	Logsunit    uint32
	Features2   uint32

	BadFeatures2        uint32
	FeaturesCompat      uint32
	FeaturesRoCompat    uint32
	FeaturesIncompat    uint32
	FeaturesLogIncompat uint32
	CRC                 uint32
	SpinoAlign          uint32
	Pquotino            uint64
	Lsn                 int64
	MetaUUID            [16]byte
}

// return (AG number), (Inode Block), (Inode Offset)
func (sb SuperBlock) InodeOffset(inodeNumber uint64) (int, uint64, uint64) {
	offsetAddress := sb.Inopblog + sb.Agblklog
	lowMask := 1<<(offsetAddress) - 1
	AGNumber := inodeNumber >> uint32(offsetAddress)

	relativeInodeNumber := inodeNumber & uint64(lowMask)
	InodeBlock := relativeInodeNumber / uint64(sb.Inopblock)
	InodeOffset := relativeInodeNumber % uint64(sb.Inopblock)

	return int(AGNumber), InodeBlock, InodeOffset
}

// return Offset
func (sb SuperBlock) InodeAbsOffset(inodeNumber uint64) uint64 {
	agNumber, blockCount, inodeOffset := sb.InodeOffset(inodeNumber)

	offset := (uint64(agNumber) * uint64(sb.Agblocks) * uint64(sb.BlockSize)) +
		(blockCount * uint64(sb.BlockSize)) +
		inodeOffset*uint64(sb.Inodesize)

	return offset
}

func (sb SuperBlock) BlockToAgNumber(n uint64) uint64 {
	return n >> uint64(sb.Agblklog)
}

func (sb SuperBlock) BlockToAgBlockNumber(n uint64) uint64 {
	return n & Mask64Lo(int64(sb.Agblklog))
}

func (sb SuperBlock) BlockToPhysicalOffset(n uint64) int64 {
	return int64(sb.BlockToAgNumber(n)*uint64(sb.Agblocks) + sb.BlockToAgBlockNumber(n))
}
