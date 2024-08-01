package xfs

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"unsafe"

	"golang.org/x/xerrors"

	"github.com/masahiro331/go-xfs-filesystem/log"
	"github.com/masahiro331/go-xfs-filesystem/xfs/utils"
)

var (
	InodeSupportVersion = 3

	XFS_DIR2_SPACE_SIZE  = int64(1) << (32 + XFS_DIR2_DATA_ALIGN_LOG)
	XFS_DIR2_DATA_OFFSET = XFS_DIR2_DATA_SPACE * XFS_DIR2_SPACE_SIZE
	XFS_DIR2_LEAF_OFFSET = XFS_DIR2_LEAF_SPACE * XFS_DIR2_SPACE_SIZE
	XFS_DIR2_FREE_OFFSET = XFS_DIR2_FREE_SPACE * XFS_DIR2_SPACE_SIZE

	_ Entry = &Dir2DataEntry{}
	_ Entry = &Dir2SfEntry{}
)

type Inode struct {
	inodeCore InodeCore
	// Device
	device *Device

	// S_IFDIR
	directoryLocal   *DirectoryLocal
	directoryExtents *DirectoryExtents
	directoryBtree   *Btree

	// S_IFREG
	regularExtent *RegularExtent
	regularBtree  *Btree

	// S_IFLNK
	symlinkString *SymlinkString
}

type RegularExtent struct {
	bmbtRecs []BmbtRec
}

type DirectoryExtents struct {
	bmbtRecs []BmbtRec
}

type Btree struct {
	bmbrBlock BmbrBlock
	bmbtRecs  []BmbtRec
}

type DirectoryLocal struct {
	dir2SfHdr Dir2SfHdr
	entries   []Dir2SfEntry
}

// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_format.h#L1787
type BmbtRec struct {
	L0 uint64
	L1 uint64
}

// https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/fs/xfs/libxfs/xfs_types.h#L162
type BmbtIrec struct {
	StartOff   uint64
	StartBlock uint64
	BlockCount uint64
	State      uint8
}

// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_format.h#L1761
type BmbrBlock struct {
	Level   uint16
	Numrecs uint16
	keys    []BmbtKey
	ptrs    []BmbtPtr
}

// BtreeBlock is almost BmbtBlock
// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_format.h#L1868
type BtreeBlock struct {
	Magic      uint32
	Level      uint16 // tree level, 0 is leaf block.
	Numrecs    uint16
	BbLeftsib  int64
	BbRightsib int64

	// Long version header
	// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_format.h#L1855
	BbBlockNo uint64
	BbLsn     uint64
	UUID      [16]byte
	BbOwner   uint64
	CRC       uint32
	Padding   int32
}

// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_format.h#L1821
type BmbtKey uint64

type BmbtPtr uint64

// https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/fs/xfs/libxfs/xfs_da_format.h#L203-L207
type Dir2SfHdr struct {
	Count   uint8
	I8Count uint8
	Parent  uint32
}

type Dir2Block struct {
	Header  Dir3DataHdr
	Entries []Dir2DataEntry

	UnusedEntries []Dir2DataUnused
	Leafs         []Dir2LeafEntry
	Tail          Dir2BlockTail
}

type Dir2BlockTail struct {
	Count uint32
	Stale uint32
}

type Dir2LeafEntry struct {
	Hashval uint32
	Address uint32
}

// https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/fs/xfs/libxfs/xfs_da_format.h#L320-L324
type Dir3DataHdr struct {
	Dir3BlkHdr
	Frees   [XFS_DIR2_DATA_FD_COUNT]Dir2DataFree
	Padding uint32
}

// https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/fs/xfs/libxfs/xfs_da_format.h#L311-L318
type Dir3BlkHdr struct {
	Magic    uint32
	CRC      uint32
	BlockNo  uint64
	Lsn      uint64
	MetaUUID [16]byte
	Owner    uint64
}

// https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/fs/xfs/libxfs/xfs_da_format.h#L353-L358
type Dir2DataUnused struct {
	Freetag uint16
	Length  uint16
	/* variable offset */
	Tag uint16
}

type Dir2DataFree struct {
	Offset uint16
	Length uint16
}

type Entry interface {
	Name() string
	FileType() uint8
	InodeNumber() uint64
}

// https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/fs/xfs/libxfs/xfs_da_format.h#L339-L345
type Dir2DataEntry struct {
	Inumber   uint64
	Namelen   uint8
	EntryName string
	Filetype  uint8
	Tag       uint16
}

// https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/fs/xfs/libxfs/xfs_da_format.h#L209-L220
type Dir2SfEntry struct {
	Namelen   uint8
	Offset    [2]uint8
	EntryName string
	Filetype  uint8
	Inumber   uint64
	Inumber32 uint32
}

type Device struct{}

type SymlinkString struct {
	Name string
}

type InodeCore struct {
	Magic        uint16
	Mode         uint16
	Version      uint8
	Format       uint8
	OnLink       uint16
	UID          uint32
	GID          uint32
	NLink        uint32
	ProjId       uint16
	Padding      [8]byte
	Flushiter    uint16
	Atime        uint64
	Mtime        uint64
	Ctime        uint64
	Size         uint64
	Nblocks      uint64
	Extsize      uint32
	Nextents     uint32
	Anextents    uint16
	Forkoff      uint8
	Aformat      uint8
	Dmevmask     uint32
	Dmstate      uint16
	Flags        uint16
	Gen          uint32
	NextUnlinked uint32

	CRC         uint32
	Changecount uint64
	Lsn         uint64
	Flags2      uint64
	Cowextsize  uint32
	Padding2    [12]byte
	Crtime      uint64
	Ino         uint64
	MetaUUID    [16]byte
}

type InobtRec struct {
	Startino  uint32
	Freecount uint32
	Free      uint64
}

func (xfs *FileSystem) inodeFormatDevice(inode Inode) Inode {
	inode.device = &Device{}
	return inode
}

func (xfs *FileSystem) inodeFormatLocal(r io.Reader, inode Inode) (Inode, error) {
	if inode.inodeCore.IsDir() {
		inode.directoryLocal = &DirectoryLocal{}
		if err := binary.Read(r, binary.BigEndian, &inode.directoryLocal.dir2SfHdr); err != nil {
			return Inode{}, xerrors.Errorf("failed to read XFS_DINODE_FMT_LOCAL directory error: %w", err)
		}

		var isI8count bool
		if inode.directoryLocal.dir2SfHdr.I8Count != 0 {
			isI8count = true
		}
		for i := 0; i < int(inode.directoryLocal.dir2SfHdr.Count); i++ {
			entry, err := parseEntry(r, isI8count)
			if err != nil {
				return Inode{}, xerrors.Errorf("failed to parse entries[%d]: %w", i, err)
			}
			inode.directoryLocal.entries = append(inode.directoryLocal.entries, *entry)
		}
	} else if inode.inodeCore.IsSymlink() {
		inode.symlinkString = &SymlinkString{}
		buf := make([]byte, inode.inodeCore.Size)
		n, err := r.Read(buf)
		if err != nil {
			return Inode{}, xerrors.Errorf("failed to read XFS_DINODE_FMT_LOCAL symlink error: %w", err)
		}
		if uint64(n) != inode.inodeCore.Size {
			return Inode{}, xerrors.Errorf(ErrReadSizeFormat, n, inode.inodeCore.Size)
		}
		inode.symlinkString.Name = string(buf)
	} else {
		log.Logger.Warn("not support XFS_DINODE_FMT_LOCAL")
	}
	return inode, nil
}

func (xfs *FileSystem) parseBmbtRecs(r io.Reader, count uint32) ([]BmbtRec, error) {
	var bmbtRecs []BmbtRec
	for i := uint32(0); i < count; i++ {
		var bmbtRec BmbtRec
		if err := binary.Read(r, binary.BigEndian, &bmbtRec); err != nil {
			return nil, xerrors.Errorf("read xfs_bmbt_irec error: %w", err)
		}
		bmbtRecs = append(bmbtRecs, bmbtRec)
	}
	return bmbtRecs, nil
}

func (xfs *FileSystem) inodeFormatExtents(r io.Reader, inode Inode) (Inode, error) {
	var err error
	if inode.inodeCore.IsDir() {
		inode.directoryExtents = &DirectoryExtents{}
		inode.directoryExtents.bmbtRecs, err = xfs.parseBmbtRecs(r, inode.inodeCore.Nextents)
		if err != nil {
			return Inode{}, xerrors.Errorf("failed to parse directory bmbt recs: %w", err)
		}
	} else if inode.inodeCore.IsRegular() {
		inode.regularExtent = &RegularExtent{}
		inode.regularExtent.bmbtRecs, err = xfs.parseBmbtRecs(r, inode.inodeCore.Nextents)
		if err != nil {
			return Inode{}, xerrors.Errorf("failed to parse regular bmbt recs: %w", err)
		}
	} else if inode.inodeCore.IsSymlink() {
		log.Logger.Warn("not support XFS_DINODE_FMT_EXTENTS isSymlink")
	} else {
		log.Logger.Debugf("%+v\n", inode)
		log.Logger.Debug("not support XFS_DINODE_FMT_EXTENTS")
	}

	return inode, nil
}

func (xfs *FileSystem) walkBtree(level uint16, keys []BmbtKey, ptrs []BmbtPtr, inode Inode) (uint16, []BmbtKey, []BmbtPtr, error) {
	if level == 1 {
		return level, keys, ptrs, nil
	}

	var retKeys []BmbtKey
	var retPtrs []BmbtPtr
	for _, ptr := range ptrs {
		nodeKeys, nodePtrs, err := xfs.parseBtreeNode(int64(ptr), inode)
		if err != nil {
			return 0, nil, nil, xerrors.Errorf("parse btree node (inode: %v, ptr: %d) error: %w", inode, ptr, err)
		}
		retKeys = append(retKeys, nodeKeys...)
		retPtrs = append(retPtrs, nodePtrs...)
	}
	level--
	return xfs.walkBtree(level, retKeys, retPtrs, inode)
}

func (xfs *FileSystem) parseMultiLevelBtree(level uint16, keys []BmbtKey, ptrs []BmbtPtr, inode Inode) ([]BmbtRec, error) {
	_, leafKeys, leafPtrs, err := xfs.walkBtree(level, keys, ptrs, inode)
	if err != nil {
		return nil, xerrors.Errorf("walk Btree error: %w", err)
	}
	return xfs.parseSingleLevelBtree(leafKeys, leafPtrs)
}

func (xfs *FileSystem) parseSingleLevelBtree(keys []BmbtKey, ptrs []BmbtPtr) ([]BmbtRec, error) {
	var ret []BmbtRec
	for _, ptr := range ptrs {
		recs, err := xfs.parseBtreeLeafNode(int64(ptr))
		if err != nil {
			return nil, xerrors.Errorf("parse btree leaf node(ptr: %d) error: %w", ptr, err)
		}

		ret = append(ret, recs...)
	}
	return ret, nil
}

func (xfs *FileSystem) parseBmbtKeyPtr(r io.Reader, inode Inode, numrecs uint16) ([]BmbtKey, []BmbtPtr, error) {
	// parse bmbt keys
	var keys []BmbtKey
	for i := uint16(0); i < numrecs; i++ {
		var key BmbtKey
		if err := binary.Read(r, binary.BigEndian, &key); err != nil {
			return nil, nil, xerrors.Errorf("failed to read regular bmbt key: %w", err)
		}
		keys = append(keys, key)
	}

	// Aformat is type of attribute fork
	// 1: local
	// 2: extents
	// 3. btree
	if inode.inodeCore.Aformat != 1 && inode.inodeCore.Forkoff != 0 {
		return nil, nil, xerrors.Errorf("unsupported attribute fork error")
	}

	// read memory align
	// TODO: check please this calculation
	var tailKeysCount int
	if inode.inodeCore.Forkoff == 0 {
		// 20 is default value of key/pointer length
		tailKeysCount = 20 - int(numrecs)
	} else {
		// (Forkoff - padding / 2(key/pointers)) - numrecs
		tailKeysCount = int((inode.inodeCore.Forkoff-1)/2) - int(numrecs)
	}
	tailBuf := make([]byte, 8*tailKeysCount)
	n, err := r.Read(tailBuf)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read tail key buf: %w", err)
	}
	if n != len(tailBuf) {
		return nil, nil, xerrors.Errorf("failed to read tail buf length actual (%d), expected (%d)", n, len(tailBuf))
	}

	// parse bmbt ptr
	var ptrs []BmbtPtr
	for i := uint16(0); i < numrecs; i++ {
		var ptr BmbtPtr
		if err := binary.Read(r, binary.BigEndian, &ptr); err != nil {
			return nil, nil, xerrors.Errorf("failed to read regular bmbt key: %w", err)
		}
		ptrs = append(ptrs, ptr)
	}
	return keys, ptrs, nil
}

func (xfs *FileSystem) parseBmbrBlock(r io.Reader, inode Inode) (*BmbrBlock, error) {
	var bmbrBlock BmbrBlock
	var err error
	if err := binary.Read(r, binary.BigEndian, &bmbrBlock.Level); err != nil {
		return nil, xerrors.Errorf("binary read bmbr block level error: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &bmbrBlock.Numrecs); err != nil {
		return nil, xerrors.Errorf("binary read bmbr block numerecs error: %w", err)
	}

	bmbrBlock.keys, bmbrBlock.ptrs, err = xfs.parseBmbtKeyPtr(r, inode, bmbrBlock.Numrecs)
	if err != nil {
		return nil, xerrors.Errorf("parse bmbr key-ptr error: %w", err)
	}
	return &bmbrBlock, nil
}

func (xfs *FileSystem) inodeFormatBtree(r io.Reader, inode Inode) (Inode, error) {
	bmbrBlock, err := xfs.parseBmbrBlock(r, inode)
	if err != nil {
		return Inode{}, xerrors.Errorf("parse bmbr block error: %w", err)
	}
	btree := &Btree{
		bmbrBlock: *bmbrBlock,
	}
	if bmbrBlock.Level == 1 {
		btree.bmbtRecs, err = xfs.parseSingleLevelBtree(
			bmbrBlock.keys,
			bmbrBlock.ptrs,
		)
		if err != nil {
			return Inode{}, xerrors.Errorf("parse single level btree error: %w", err)
		}
	} else if bmbrBlock.Level > 1 {
		btree.bmbtRecs, err = xfs.parseMultiLevelBtree(
			bmbrBlock.Level,
			bmbrBlock.keys,
			bmbrBlock.ptrs,
			inode,
		)
		if err != nil {
			return Inode{}, xerrors.Errorf("parse multi level btree error: %w", err)
		}
	}
	if inode.inodeCore.IsRegular() {
		inode.regularBtree = btree
	}
	if inode.inodeCore.IsDir() {
		inode.directoryBtree = btree
	}

	return inode, nil
}

func (xfs *FileSystem) ParseInode(ino uint64) (*Inode, error) {
	var inode Inode
	c, ok := xfs.cache.Get(inodeCacheKey(ino))
	if ok {
		i := c.(Inode)
		if ok {
			return &i, nil
		}
	}

	_, err := xfs.seekInode(ino)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek inode: %w", err)
	}

	sectorReader, err := utils.NewSectorReader(int(xfs.PrimaryAG.SuperBlock.Inodesize))
	if err != nil {
		return nil, xerrors.Errorf("failed to create sector reader: %w", err)
	}
	buf, err := sectorReader.ReadSector(xfs.r)
	if err != nil {
		return nil, xerrors.Errorf("failed to read sector: %w", err)
	}
	r := bytes.NewReader(buf)

	if err := binary.Read(r, binary.BigEndian, &inode.inodeCore); err != nil {
		return nil, xerrors.Errorf("failed to read InodeCore: %w", err)
	}

	if inode.inodeCore.Magic != XFS_DINODE_MAGIC {
		return nil, xerrors.Errorf("invalid magic byte error")
	}

	if !inode.inodeCore.isSupported() {
		return nil, xerrors.Errorf("not support inode version %d", inode.inodeCore.Version)
	}

	switch inode.inodeCore.Format {
	case XFS_DINODE_FMT_DEV:
		inode = xfs.inodeFormatDevice(inode)
	case XFS_DINODE_FMT_LOCAL:
		inode, err = xfs.inodeFormatLocal(r, inode)
		if err != nil {
			log.Logger.Debug("\n", hex.Dump(buf))
			return nil, xerrors.Errorf("parse inode format local: %w", err)
		}
	case XFS_DINODE_FMT_EXTENTS:
		inode, err = xfs.inodeFormatExtents(r, inode)
		if err != nil {
			log.Logger.Debug("\n", hex.Dump(buf))
			return nil, xerrors.Errorf("parse inode format extents: %w", err)
		}
	case XFS_DINODE_FMT_BTREE:
		inode, err = xfs.inodeFormatBtree(r, inode)
		if err != nil {
			log.Logger.Debug("\n", hex.Dump(buf))
			return nil, xerrors.Errorf("parse inode format btree: %w", err)
		}
	case XFS_DINODE_FMT_UUID:
		log.Logger.Warn("not support XFS_DINODE_FMT_UUID")
	case XFS_DINODE_FMT_RMAP:
		log.Logger.Warn("not support XFS_DINODE_FMT_RMAP")
	default:
		log.Logger.Warnf("not support inode format(%d)", inode.inodeCore.Format)
	}

	// TODO: support extend attribute fork , see. Chapter 19 Extended Attributes
	// if inode.inodeCore.Forkoff != 0 {
	// 	panic("has extend attribute fork")
	// }

	xfs.cache.Add(inodeCacheKey(ino), inode)
	return &inode, nil
}

func (xfs *FileSystem) parseBtreeBlock(r io.Reader) (*BtreeBlock, error) {
	btreeBlock := &BtreeBlock{}
	if err := binary.Read(r, binary.BigEndian, btreeBlock); err != nil {
		return nil, xerrors.Errorf("failed to read b+tree block: %w", err)
	}
	if btreeBlock.Magic != XFS_BMAP_CRC_MAGIC {
		return nil, xerrors.Errorf("unsupported block header: (%d), expected BMAP_CRC_MAGIC", btreeBlock.Magic)
	}
	return btreeBlock, nil
}

func (xfs *FileSystem) parseBtreeNode(blockNumber int64, inode Inode) ([]BmbtKey, []BmbtPtr, error) {
	physicalBlockOffset := xfs.PrimaryAG.SuperBlock.BlockToPhysicalOffset(uint64(blockNumber))
	_, err := xfs.seekBlock(physicalBlockOffset)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to seek block: %w", err)
	}
	b, err := xfs.readBlock(1)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read block: %w", err)
	}

	r := bytes.NewReader(b)
	btreeBlock, err := xfs.parseBtreeBlock(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("parse btree node (offset: %d) error: %w", blockNumber, err)
	}

	keys, ptrs, err := xfs.parseBmbtKeyPtr(r, inode, btreeBlock.Numrecs)
	if err != nil {
		return nil, nil, xerrors.Errorf("parse bmbr key-ptr error: %w", err)
	}
	return keys, ptrs, nil
}

func (xfs *FileSystem) parseBtreeLeafNode(blockNumber int64) ([]BmbtRec, error) {
	physicalBlockOffset := xfs.PrimaryAG.SuperBlock.BlockToPhysicalOffset(uint64(blockNumber))
	_, err := xfs.seekBlock(physicalBlockOffset)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek block: %w", err)
	}
	b, err := xfs.readBlock(1)
	if err != nil {
		return nil, xerrors.Errorf("failed to read block: %w", err)
	}

	r := bytes.NewReader(b)
	btreeBlock, err := xfs.parseBtreeBlock(r)
	if err != nil {
		return nil, xerrors.Errorf("parse btree node (offset: %d) error: %w", blockNumber*int64(xfs.PrimaryAG.SuperBlock.BlockSize), err)
	}

	if btreeBlock.Level > 1 {
		return nil, xerrors.Errorf("unsupported deep b+tree level: %d", btreeBlock.Level)
	}

	recs := []BmbtRec{}
	for i := uint16(0); i < btreeBlock.Numrecs; i++ {
		var bmbtRec BmbtRec
		if err := binary.Read(r, binary.BigEndian, &bmbtRec); err != nil {
			return nil, xerrors.Errorf("failed to read extents xfs_bmbt_irec: %w", err)
		}
		recs = append(recs, bmbtRec)
	}
	return recs, nil
}

// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_bmap_btree.c#L316
func BmbrMaxRecs(blocklen int) int {
	return blocklen / 16
}

// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_format.h#L1077-L1078
func (xfs *FileSystem) DataForkSize(forkoff uint8) int {
	if forkoff > 0 {
		return int(forkoff) << 3
	}
	return int(xfs.PrimaryAG.SuperBlock.Inodesize) - 176 // v3 InodeCore size
}

func (i *Inode) AttributeOffset() uint32 {
	return uint32(i.inodeCore.Forkoff)*8 + INODEV3_SIZE
}

// Parse XDB3block, XDB3 block is single block architecture
func (xfs *FileSystem) parseXDB3Block(r io.Reader) ([]Dir2DataEntry, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to read XDB3 block reader: %w", err)
	}
	var tail Dir2BlockTail

	tailBlockOffset := len(buf) - int(unsafe.Sizeof(tail))
	if tailBlockOffset > len(buf) {
		return nil, xerrors.Errorf("failed to calculate tail block offset: %d", tailBlockOffset)
	}
	tailReader := bytes.NewReader(buf[tailBlockOffset:])
	if err := binary.Read(tailReader, binary.BigEndian, &tail); err != nil {
		return nil, xerrors.Errorf("failed to read tail binary: %w", err)
	}

	dataEndOffset := uint32(len(buf)) - (tail.Count*LEAF_ENTRY_SIZE + uint32(unsafe.Sizeof(tail)))
	if dataEndOffset > uint32(len(buf)) {
		return nil, xerrors.Errorf("failed to calculate data end offset: %d", dataEndOffset)
	}
	reader := bytes.NewReader(buf[:dataEndOffset])

	dir2DataEntries, err := xfs.parseDir2DataEntry(reader)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse dir2 Data Entry: %w", err)
	}
	return dir2DataEntries, nil
}

// Parse XDD3block, XDD3 block is multi block architecture
func (xfs *FileSystem) parseXDD3Block(r io.Reader) ([]Dir2DataEntry, error) {
	dir2DataEntries, err := xfs.parseDir2DataEntry(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse dir2 Data Entry: %w", err)
	}
	return dir2DataEntries, nil
}

func (xfs *FileSystem) parseDir2DataEntry(r io.Reader) ([]Dir2DataEntry, error) {
	entries := []Dir2DataEntry{}
	for {
		entry := Dir2DataEntry{}

		// Parse Inode number
		if err := binary.Read(r, binary.BigEndian, &entry.Inumber); err != nil {
			if err == io.EOF {
				return entries, nil
			}
			return nil, xerrors.Errorf("failed to read inumber binary: %w", err)
		}

		if (entry.Inumber >> 48) == XFS_DIR2_DATA_FREE_TAG {
			freeLen := (entry.Inumber >> 32) & Mask64Lo(16)
			if freeLen != 8 {
				// Read FreeTag tail
				_, err := r.Read(make([]byte, freeLen-0x08))
				if err != nil {
					return nil, xerrors.Errorf("failed to read unused padding: %w", err)
				}
			}
			continue
		}

		// Parse Name length
		if err := binary.Read(r, binary.BigEndian, &entry.Namelen); err != nil {
			return nil, xerrors.Errorf("failed to read name length: %w", err)
		}

		// Parse Name
		nameBuf := make([]byte, entry.Namelen)
		n, err := r.Read(nameBuf)
		if err != nil {
			return nil, xerrors.Errorf("failed to read name: %w", err)
		}
		if n != int(entry.Namelen) {
			return nil, xerrors.Errorf("failed to read name: expected namelen(%d) actual(%d)", entry.Namelen, n)
		}
		entry.EntryName = string(nameBuf)

		// Parse FileType
		if err := binary.Read(r, binary.BigEndian, &entry.Filetype); err != nil {
			return nil, xerrors.Errorf("failed to read file type: %w", err)
		}

		// Read Alignment, Dir2DataEntry is 8byte alignment
		align := (int(unsafe.Sizeof(entry.Inumber)) +
			int(unsafe.Sizeof(entry.Namelen)) +
			int(unsafe.Sizeof(entry.Filetype)) +
			int(unsafe.Sizeof(entry.Tag)) +
			int(entry.Namelen)) % 8
		if align != 0 {
			n, err = r.Read(make([]byte, 8-align))
			if err != nil {
				return nil, xerrors.Errorf("failed to read alignment: %w", err)
			}
			if n != int(8-align) {
				return nil, xerrors.Errorf("failed to read alignment: expected (%d) actual(%d)", 8-align, n)
			}
		}

		// Read Tag
		if err := binary.Read(r, binary.BigEndian, &entry.Tag); err != nil {
			return nil, xerrors.Errorf("failed to read tag: %w", err)
		}

		entries = append(entries, entry)
	}
}

func (xfs *FileSystem) parseDir2Block(bmbtIrec BmbtIrec) ([]Dir2DataEntry, error) {
	block := Dir2Block{}
	/*
		Skip Leaf and Free node.
		The "leaf" block has a special offset defined by XFS_DIR2_LEAF_OFFSET. Currently, this is 32GB and in the extent view,
		a block offset of 32GB / sb_blocksize. On a 4KB block filesystem, this is 0x800000 (8388608 decimal).
	*/
	if int64(bmbtIrec.StartOff)*int64(xfs.PrimaryAG.SuperBlock.BlockSize) >= int64(XFS_DIR2_LEAF_OFFSET) {
		return nil, nil
	}

	var buf []byte
	for blockOffset := bmbtIrec.StartBlock; blockOffset < bmbtIrec.StartBlock+bmbtIrec.BlockCount; blockOffset++ {
		physicalBlockOffset := xfs.PrimaryAG.SuperBlock.BlockToPhysicalOffset(blockOffset)
		_, err := xfs.seekBlock(physicalBlockOffset)
		if err != nil {
			return nil, xerrors.Errorf("failed to seek block: %w", err)
		}
		blockData, err := utils.ReadBlock(xfs.r)
		if err != nil {
			return nil, xerrors.Errorf("failed to read block: %w", err)
		}
		buf = append(buf, blockData...)

		// if the next block is not a leader, it is a continuation of the previous block
		if blockOffset != bmbtIrec.StartBlock+bmbtIrec.BlockCount-1 && // not last block
			!xfs.nextBlockIsLeader(blockOffset) { // not leader
			continue
		}

		// if the next block is a leader, it is the last block of the directory
		magicBytes := binary.BigEndian.Uint32(buf[:4])
		reader := bytes.NewReader(buf)
		if err := binary.Read(reader, binary.BigEndian, &block.Header); err != nil {
			return nil, xerrors.Errorf("failed to parse dir3 data header error: %w", err)
		}
		switch magicBytes {
		case XFS_DIR3_DATA_MAGIC:
			entries, err := xfs.parseXDD3Block(reader)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse XDD3 block: %w", err)
			}
			block.Entries = append(block.Entries, entries...)
		case XFS_DIR3_BLOCK_MAGIC:
			entries, err := xfs.parseXDB3Block(reader)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse XDB3 block: %w", err)
			}
			block.Entries = append(block.Entries, entries...)
		default:
			return nil, xerrors.Errorf("unknown magic bytes: %x", magicBytes)
		}

		// reset buf
		buf = []byte{}
	}

	return block.Entries, nil
}

func (xfs *FileSystem) nextBlockIsLeader(blockOffset uint64) bool {
	physicalBlockOffset := xfs.PrimaryAG.SuperBlock.BlockToPhysicalOffset(blockOffset + 1)
	xfs.seekBlock(physicalBlockOffset)
	blockData, _ := utils.ReadBlock(xfs.r)

	magic := binary.BigEndian.Uint32(blockData[:4])
	return magic == XFS_DIR3_DATA_MAGIC || magic == XFS_DIR3_BLOCK_MAGIC
}

func parseEntry(r io.Reader, i8count bool) (*Dir2SfEntry, error) {
	var entry Dir2SfEntry
	if err := binary.Read(r, binary.BigEndian, &entry.Namelen); err != nil {
		return nil, err
	}

	if err := binary.Read(r, binary.BigEndian, &entry.Offset); err != nil {
		return nil, err
	}
	buf := make([]byte, entry.Namelen)
	i, err := r.Read(buf)
	if err != nil {
		return nil, err
	}
	if i != int(entry.Namelen) {
		return nil, xerrors.Errorf("read name error: %s", string(buf))
	}
	entry.EntryName = string(buf)
	if err := binary.Read(r, binary.BigEndian, &entry.Filetype); err != nil {
		return nil, err
	}

	if i8count {
		if err := binary.Read(r, binary.BigEndian, &entry.Inumber); err != nil {
			return nil, err
		}
	} else {
		if err := binary.Read(r, binary.BigEndian, &entry.Inumber32); err != nil {
			return nil, err
		}
		entry.Inumber = uint64(entry.Inumber32)
	}

	return &entry, nil
}

func (ic InodeCore) IsDir() bool {
	return ic.Mode&0x4000 != 0 && ic.Mode&0x8000 == 0
}

func (ic InodeCore) IsRegular() bool {
	return ic.Mode&0x8000 != 0 && ic.Mode&0x4000 == 0
}

func (ic InodeCore) IsSocket() bool {
	return ic.Mode&0xC000 != 0
}

func (ic InodeCore) IsSymlink() bool {
	return ic.Mode&0xA000 != 0
}

func (ic InodeCore) isSupported() bool {
	return ic.Version == uint8(InodeSupportVersion)
}

// https://github.com/torvalds/linux/blob/d2b6f8a179194de0ffc4886ffc2c4358d86047b8/fs/xfs/libxfs/xfs_bmap_btree.c#L60
func (b BmbtRec) Unpack() BmbtIrec {
	return BmbtIrec{
		StartOff:   (b.L0 & Mask64Lo(64-BMBT_EXNTFLAG_BITLEN)) >> 9,
		StartBlock: ((b.L0 & Mask64Lo(9)) << 43) | (b.L1 >> 21),
		BlockCount: b.L1 & Mask64Lo(21),
	}
}

func Mask64Lo(n int64) uint64 {
	return (1 << n) - 1
}

func (e Dir2SfEntry) FileType() uint8 {
	return e.Filetype
}

func (e Dir2DataEntry) FileType() uint8 {
	return e.Filetype
}

func (e Dir2SfEntry) Name() string {
	return e.EntryName
}

func (e Dir2DataEntry) Name() string {
	return e.EntryName
}

func (e Dir2SfEntry) InodeNumber() uint64 {
	return e.Inumber
}

func (e Dir2DataEntry) InodeNumber() uint64 {
	return e.Inumber
}
