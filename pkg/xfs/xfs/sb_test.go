package xfs_test

import (
	"testing"

	"github.com/masahiro331/go-xfs-filesystem/xfs"
)

/*
How to search Inode.

Root inode is Superblock RootIno
Rootino: 96

inopblock (InodePerBlocks log): 3
Agblklog (AG block log): 19
relative inode mask: inopblock + Agblklog
3 + 19 = 22

rootino:96 =binary=> 00   00 0000 0000 0000 0110 0000
                     AG   \---- relative inode -----/

AG number: 0
Inode block:  (Inode Number) div (Block Per Inodes) = 12
Inode offset: (Inode Number) mod (Block Per Inodes) = 0
Physical Offset: (Inode block * block size) + (Inode offset * inosize)

(12 * 4096) + (0 * 64) = 49152 = 0xC000
0xC000 is root inode offset.
*/

func TestSuperBlock_InodeOffset(t *testing.T) {
	type fields struct {
		Inopblog  uint8
		Agblklog  uint8
		Inopblock uint16
	}
	type args struct {
		inodeNumber uint64
	}
	tests := []struct {
		name                string
		fields              fields
		args                args
		expectedAgNumber    int
		expectedInodeBlock  uint64
		expectedInodeOffset uint64
	}{
		{
			name: "happy path root inode",
			fields: fields{
				Inopblog:  4,
				Agblklog:  22,
				Inopblock: 16,
			},
			args: args{
				inodeNumber: 128,
			},
			expectedAgNumber:    0,
			expectedInodeBlock:  8,
			expectedInodeOffset: 0,
		},
		{
			name: "happy path other root inode",
			fields: fields{
				Inopblog:  3,
				Agblklog:  19,
				Inopblock: 8,
			},
			args: args{
				inodeNumber: 96,
			},
			expectedAgNumber:    0,
			expectedInodeBlock:  12,
			expectedInodeOffset: 0,
		},
		{
			name: "happy path root inode + 1",
			fields: fields{
				Inopblog:  3,
				Agblklog:  19,
				Inopblock: 8,
			},
			args: args{
				inodeNumber: 97,
			},
			expectedAgNumber:    0,
			expectedInodeBlock:  12,
			expectedInodeOffset: 1,
		},
		{
			/*
				bin(160) = 0b10100000
				3 + 19 = 22

				00 0000000000000010100000
				|   +-> relative inode
				+-> AgNumber

				AG number: 0
				Inode block: 160 / 8 = 20
				Inode offset: 160 % 8 = 0
			*/
			name: "happy path other block",
			fields: fields{
				Inopblog:  3,
				Agblklog:  19,
				Inopblock: 8,
			},
			args: args{
				inodeNumber: 160,
			},
			expectedAgNumber:    0,
			expectedInodeBlock:  20,
			expectedInodeOffset: 0,
		},
		{
			/*
				bin(4194304) = '0b10000000000000000000000'
				3 + 19 = 22

				01  0000000000000000000000
				|   +-> relative inode
				+-> AgNumber
			*/
			name: "happy path secondary ag inode, (2 ** 19 * 8)",
			fields: fields{
				Inopblog:  3,
				Agblklog:  19,
				Inopblock: 8,
			},
			args: args{
				inodeNumber: 4194304,
			},
			expectedAgNumber:    1,
			expectedInodeBlock:  0,
			expectedInodeOffset: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := xfs.SuperBlock{
				Inopblock: tt.fields.Inopblock,
				Inopblog:  tt.fields.Inopblog,
				Agblklog:  tt.fields.Agblklog,
			}
			got, got1, got2 := sb.InodeOffset(tt.args.inodeNumber)
			if got != tt.expectedAgNumber {
				t.Errorf("AG Number got = %v, want %v", got, tt.expectedAgNumber)
			}
			if got1 != tt.expectedInodeBlock {
				t.Errorf("Inode Block got = %v, want %v", got1, tt.expectedInodeBlock)
			}
			if got2 != tt.expectedInodeOffset {
				t.Errorf("Inode Offset got = %v, want %v", got2, tt.expectedInodeOffset)
			}
		})
	}
}

func TestSuperBlock_InodeAbsOffset(t *testing.T) {
	type fields struct {
		Inopblog  uint8
		Agblklog  uint8
		Inopblock uint16
		BlockSize uint32
		InodeSize uint16
	}
	type args struct {
		inodeNumber uint64
	}
	tests := []struct {
		name                   string
		fields                 fields
		args                   args
		expectedPhysicalOffset uint64
	}{
		{
			name: "happy path root inode offset",
			fields: fields{
				Inopblog:  4,
				Agblklog:  22,
				Inopblock: 16,
				BlockSize: 4096,
				InodeSize: 256,
			},
			args: args{
				inodeNumber: 128,
			},
			expectedPhysicalOffset: 32768,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := xfs.SuperBlock{
				Inopblock: tt.fields.Inopblock,
				Inopblog:  tt.fields.Inopblog,
				Agblklog:  tt.fields.Agblklog,
				Inodesize: tt.fields.InodeSize,
				BlockSize: tt.fields.BlockSize,
			}
			got := sb.InodeAbsOffset(tt.args.inodeNumber)
			if got != tt.expectedPhysicalOffset {
				t.Errorf("AG Number got = %v, want %v", got, tt.expectedPhysicalOffset)
			}
		})
	}
}
