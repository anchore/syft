// This code was copied from the Go std library.
// https://github.com/golang/go/blob/master/src/cmd/go/internal/version/exe.go
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//nolint
package golang

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"strings"
)

// An exe is a generic interface to an OS executable (ELF, Mach-O, PE, XCOFF).
type exe interface {
	// Close closes the underlying file.
	Close() error

	// ReadData reads and returns up to size byte starting at virtual address addr.
	ReadData(addr, size uint64) ([]byte, error)

	// ArchName returns a string that represents the CPU architecture of the executable.
	ArchName() string

	// DataStart returns the writable data segment start address.
	DataStart() uint64
}

// openExe opens file and returns it as an exe.
// we changed this signature from accpeting a string
// to a ReadCloser so we could adapt the code to the
// stereoscope api. We removed the file open methods.
func openExe(file io.ReadCloser) ([]exe, error) {
	/*
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		data := make([]byte, 16)
		if _, err := io.ReadFull(f, data); err != nil {
			return nil, err
		}
		f.Seek(0, 0)
	*/
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	f := io.NewSectionReader(r, 0, int64(len(data)))
	if bytes.HasPrefix(data, []byte("\x7FELF")) {
		e, err := elf.NewFile(f)
		if err != nil {
			return nil, err
		}

		return []exe{&elfExe{file, e}}, nil
	}

	if bytes.HasPrefix(data, []byte("MZ")) {
		e, err := pe.NewFile(f)
		if err != nil {
			return nil, err
		}
		return []exe{&peExe{file, e}}, nil
	}

	if bytes.HasPrefix(data, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(data[1:], []byte("\xFA\xED\xFE")) {
		e, err := macho.NewFile(f)
		if err != nil {
			return nil, err
		}
		return []exe{&machoExe{file, e}}, nil
	}

	// adding macho multi-architecture support (both for 64bit and 32 bit)... this case is not in the stdlib yet
	if bytes.HasPrefix(data, []byte("\xCA\xFE\xBA\xBE")) || bytes.HasPrefix(data, []byte("\xCA\xFE\xBA\xBF")) {
		fatExe, err := macho.NewFatFile(f)
		if err != nil {
			return nil, err
		}
		var exes []exe
		for _, arch := range fatExe.Arches {
			exes = append(exes, &machoExe{file, arch.File})
		}
		return exes, nil
	}

	return nil, fmt.Errorf("unrecognized executable format")
}

// elfExe is the ELF implementation of the exe interface.
// updated os to be io.ReadCloser to interopt with stereoscope
type elfExe struct {
	os io.ReadCloser
	f  *elf.File
}

func (x *elfExe) Close() error {
	return x.os.Close()
}

func (x *elfExe) ArchName() string {
	return cleanElfArch(x.f.Machine)
}

func cleanElfArch(machine elf.Machine) string {
	return strings.TrimPrefix(strings.ToLower(machine.String()), "em_")
}

func (x *elfExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, prog := range x.f.Progs {
		if prog.Vaddr <= addr && addr <= prog.Vaddr+prog.Filesz-1 {
			n := prog.Vaddr + prog.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *elfExe) DataStart() uint64 {
	for _, s := range x.f.Sections {
		if s.Name == ".go.buildinfo" {
			return s.Addr
		}
	}
	for _, p := range x.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return p.Vaddr
		}
	}
	return 0
}

// peExe is the PE (Windows Portable Executable) implementation of the exe interface.
type peExe struct {
	os io.ReadCloser
	f  *pe.File
}

func (x *peExe) Close() error {
	return x.os.Close()
}

func (x *peExe) ArchName() string {
	// from: debug/pe/pe.go
	switch x.f.Machine {
	case pe.IMAGE_FILE_MACHINE_AM33:
		return "amd33"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "armnt"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_EBC:
		return "ebc"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "i386"
	case pe.IMAGE_FILE_MACHINE_IA64:
		return "ia64"
	case pe.IMAGE_FILE_MACHINE_M32R:
		return "m32r"
	case pe.IMAGE_FILE_MACHINE_MIPS16:
		return "mips16"
	case pe.IMAGE_FILE_MACHINE_MIPSFPU:
		return "mipsfpu"
	case pe.IMAGE_FILE_MACHINE_MIPSFPU16:
		return "mipsfpu16"
	case pe.IMAGE_FILE_MACHINE_POWERPC:
		return "ppc"
	case pe.IMAGE_FILE_MACHINE_POWERPCFP:
		return "ppcfp"
	case pe.IMAGE_FILE_MACHINE_R4000:
		return "r4000"
	case pe.IMAGE_FILE_MACHINE_SH3:
		return "sh3"
	case pe.IMAGE_FILE_MACHINE_SH3DSP:
		return "sh3dsp"
	case pe.IMAGE_FILE_MACHINE_SH4:
		return "sh4"
	case pe.IMAGE_FILE_MACHINE_SH5:
		return "sh5"
	case pe.IMAGE_FILE_MACHINE_THUMB:
		return "thumb"
	case pe.IMAGE_FILE_MACHINE_WCEMIPSV2:
		return "wcemipsv2"
	default:
		return fmt.Sprintf("unknown-pe-machine-%d", x.f.Machine)
	}
}

func (x *peExe) imageBase() uint64 {
	switch oh := x.f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0
}

func (x *peExe) ReadData(addr, size uint64) ([]byte, error) {
	addr -= x.imageBase()
	for _, sect := range x.f.Sections {
		if uint64(sect.VirtualAddress) <= addr && addr <= uint64(sect.VirtualAddress+sect.Size-1) {
			n := uint64(sect.VirtualAddress+sect.Size) - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := sect.ReadAt(data, int64(addr-uint64(sect.VirtualAddress)))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *peExe) DataStart() uint64 {
	// Assume data is first writable section.
	const (
		IMAGE_SCN_CNT_CODE               = 0x00000020
		IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
		IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
		IMAGE_SCN_MEM_EXECUTE            = 0x20000000
		IMAGE_SCN_MEM_READ               = 0x40000000
		IMAGE_SCN_MEM_WRITE              = 0x80000000
		IMAGE_SCN_MEM_DISCARDABLE        = 0x2000000
		IMAGE_SCN_LNK_NRELOC_OVFL        = 0x1000000
		IMAGE_SCN_ALIGN_32BYTES          = 0x600000
	)
	for _, sect := range x.f.Sections {
		if sect.VirtualAddress != 0 && sect.Size != 0 &&
			sect.Characteristics&^IMAGE_SCN_ALIGN_32BYTES == IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE {
			return uint64(sect.VirtualAddress) + x.imageBase()
		}
	}
	return 0
}

// machoExe is the Mach-O (Apple macOS/iOS) implementation of the exe interface.
type machoExe struct {
	os io.ReadCloser
	f  *macho.File
}

func (x *machoExe) Close() error {
	return x.os.Close()
}

func (x *machoExe) ArchName() string {
	return cleanMachoArch(x.f.Cpu)
}

func cleanMachoArch(cpu macho.Cpu) string {
	return strings.TrimPrefix(strings.ToLower(cpu.String()), "cpu")
}

func (x *machoExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= addr && addr <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			n := seg.Addr + seg.Filesz - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := seg.ReadAt(data, int64(addr-seg.Addr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *machoExe) DataStart() uint64 {
	// Look for section named "__go_buildinfo".
	for _, sec := range x.f.Sections {
		if sec.Name == "__go_buildinfo" {
			return sec.Addr
		}
	}
	// Try the first non-empty writable segment.
	const RW = 3
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if ok && seg.Addr != 0 && seg.Filesz != 0 && seg.Prot == RW && seg.Maxprot == RW {
			return seg.Addr
		}
	}
	return 0
}

/*
// xcoffExe is the XCOFF (AIX eXtended COFF) implementation of the exe interface.
type xcoffExe struct {
	os *os.File
	f  *xcoff.File
}

func (x *xcoffExe) Close() error {
	return x.os.Close()
}

func (x *xcoffExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, sect := range x.f.Sections {
		if uint64(sect.VirtualAddress) <= addr && addr <= uint64(sect.VirtualAddress+sect.Size-1) {
			n := uint64(sect.VirtualAddress+sect.Size) - addr
			if n > size {
				n = size
			}
			data := make([]byte, n)
			_, err := sect.ReadAt(data, int64(addr-uint64(sect.VirtualAddress)))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *xcoffExe) DataStart() uint64 {
	return x.f.SectionByType(xcoff.STYP_DATA).VirtualAddress
}
*/
