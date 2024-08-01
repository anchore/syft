package xfs

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/masahiro331/go-xfs-filesystem/xfs/utils"

	"golang.org/x/xerrors"
)

type AG struct {
	SuperBlock SuperBlock
	Agi        AGI
	Agf        AGF
	Agfl       AGFL

	Ab3b AB3B
	Ab3c AB3C
	Iab3 IAB3
	Fib3 FIB3
}

type AGFL struct {
	Magicnum uint32
	Seqno    uint32
	UUID     [16]byte
	Lsn      uint64
	CRC      uint32
	Bno      [118]uint32
}

type AGF struct {
	Magicnum   uint32
	Versionnum uint32
	Seqno      uint32
	Length     uint32

	Roots  [3]uint32
	Levels [3]uint32

	Flfirst   uint32
	Fllast    uint32
	Flcount   uint32
	Freeblks  uint32
	Longest   uint32
	Btreeblks uint32
	UUID      [16]byte

	RmapBlocks     uint32
	RefcountBlocks uint32
	RefcountRoot   uint32
	RefcountLevel  uint32
	Spare64        [112]byte
	Lsn            uint64
	CRC            uint32
	Spare2         uint32
}

type AGI struct {
	Magicnum   uint32
	Versionnum uint32
	Seqno      uint32
	Length     uint32
	Count      uint32
	Root       uint32
	Level      uint32
	Freecount  uint32
	Newino     uint32
	Dirino     uint32
	Unlinked   [256]byte
	UUID       [16]byte
	CRC        uint32
	Pad32      uint32
	Lsn        uint64
	FreeRoot   uint32
	FreeLevel  uint32
	Iblocks    uint32
	Fblocks    uint32
}

type IAB3 struct {
	Header BtreeShortBlock
	Inodes []InobtRec
}

type FIB3 struct {
	BtreeShortBlock
}

type AB3B struct {
	BtreeShortBlock
}

type AB3C struct {
	BtreeShortBlock
}

type BtreeShortBlock struct {
	Magicnum uint32
	Level    uint16
	Numrecs  uint16
	Leftsib  uint32
	Rightsib uint32
	Blkno    uint64
	Lsn      uint64
	UUID     [16]byte
	Owner    uint32
	CRC      uint32
}

func parseSuperBlock(r io.Reader) (SuperBlock, error) {
	var sb SuperBlock
	sectorReader := utils.DefaultSectorReader()
	buf, err := sectorReader.ReadSector(r)
	if err != nil {
		return SuperBlock{}, xerrors.Errorf("failed to create superblock reader: %w", err)
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &sb); err != nil {
		return SuperBlock{}, xerrors.Errorf("failed to read superblock: %w", err)
	}
	if sb.Magicnum != XFS_SB_MAGIC {
		return SuperBlock{}, xerrors.Errorf("failed to parse superblock magic byte error: %08x", sb.Magicnum)
	}

	if sb.Sectsize != utils.SectorSize {
		completeSector := int(sb.Sectsize - utils.SectorSize)
		buf := make([]byte, completeSector)
		i, err := r.Read(buf)
		if err != nil {
			return SuperBlock{}, xerrors.Errorf("failed to read: %w", err)
		}
		if i != completeSector {
			return SuperBlock{}, xerrors.Errorf("sector size error, read %d byte", i)
		}
	}
	return sb, nil
}

func parseAGF(sectorReader utils.SectorReader, r io.Reader) (AGF, error) {
	var agf AGF
	buf, err := sectorReader.ReadSector(r)
	if err != nil {
		return AGF{}, xerrors.Errorf("failed to create agf reader: %w", err)
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &agf); err != nil {
		return AGF{}, xerrors.Errorf("failed to read agf: %w", err)
	}
	if agf.Magicnum != XFS_AGF_MAGIC {
		return AGF{}, xerrors.Errorf("failed to parse agf magic byte error: %08x", agf.Magicnum)
	}
	return agf, nil
}

func parseAGI(sectorReader utils.SectorReader, r io.Reader) (AGI, error) {
	var agi AGI
	buf, err := sectorReader.ReadSector(r)
	if err != nil {
		return AGI{}, xerrors.Errorf("failed to create agi reader: %w", err)
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &agi); err != nil {
		return AGI{}, xerrors.Errorf("failed to read agi: %w", err)
	}
	if agi.Magicnum != XFS_AGI_MAGIC {
		return AGI{}, xerrors.Errorf("failed to parse agi magic byte error: %08x", agi.Magicnum)
	}
	return agi, nil
}

func parseAGFL(sectorReader utils.SectorReader, r io.Reader) (AGFL, error) {
	var agfl AGFL
	buf, err := sectorReader.ReadSector(r)
	if err != nil {
		return AGFL{}, xerrors.Errorf("failed to create agfl reader: %w", err)
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &agfl); err != nil {
		return AGFL{}, xerrors.Errorf("failed to read agfl: %w", err)
	}
	if agfl.Magicnum != XFS_AGFL_MAGIC {
		return AGFL{}, xerrors.Errorf("failed to parse agfl magic byte error: %08x", agfl.Magicnum)
	}
	return agfl, nil
}

func ParseAG(reader io.Reader) (*AG, error) {
	var r io.Reader
	var ag AG
	var err error
	r = io.LimitReader(reader, int64(utils.BlockSize))
	ag.SuperBlock, err = parseSuperBlock(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse super block: %w", err)
	}

	sectorReader, err := utils.NewSectorReader(int(ag.SuperBlock.Sectsize))
	if err != nil {
		return nil, xerrors.Errorf("failed to create chunk reader: %w", err)
	}

	r = io.LimitReader(reader, int64(utils.BlockSize))
	ag.Agf, err = parseAGF(sectorReader, r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse agf block: %w", err)
	}

	r = io.LimitReader(reader, int64(utils.BlockSize))
	ag.Agi, err = parseAGI(sectorReader, r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse agi block: %w", err)
	}

	r = io.LimitReader(reader, int64(utils.BlockSize))
	ag.Agfl, err = parseAGFL(sectorReader, r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse agfl block: %w", err)
	}

	return &ag, nil
}
