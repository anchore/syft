package executable

import (
	"debug/buildinfo"
	"debug/elf"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/file"
)

var (
	clangVersionPattern = regexp.MustCompile(`clang version (\d+\.\d+\.\d+)`)
	gccVersionPattern   = regexp.MustCompile(`GCC: \([^)]+\) (\d+\.\d+\.\d+)`)
)

// elfGolangToolchainEvidence attempts to extract Go toolchain information from the ELF file.
func golangToolchainEvidence(reader io.ReaderAt) *file.Toolchain {
	bi, err := buildinfo.Read(reader)
	if err != nil || bi == nil {
		// not a golang binary
		return nil
	}
	return &file.Toolchain{
		Name:    "go",
		Version: bi.GoVersion,
		Kind:    file.ToolchainKindCompiler,
	}
}

// cToolchainEvidence attempts to extract C/C++ compiler information from the ELF .comment section.
// This detects GCC and Clang compilers based on their version strings.
func cToolchainEvidence(f *elf.File) *file.Toolchain {
	commentSection := f.Section(".comment")
	if commentSection == nil {
		return nil
	}

	data, err := commentSection.Data()
	if err != nil {
		return nil
	}

	// the .comment section contains null-terminated strings
	comments := strings.Split(string(data), "\x00")

	// check for clang first since clang binaries often have both GCC and clang entries
	// (clang includes GCC compatibility info)
	for _, comment := range comments {
		if match := clangVersionPattern.FindStringSubmatch(comment); match != nil {
			return &file.Toolchain{
				Name:    "clang",
				Version: match[1],
				Kind:    file.ToolchainKindCompiler,
			}
		}
	}

	// if not clang, check for GCC
	for _, comment := range comments {
		if match := gccVersionPattern.FindStringSubmatch(comment); match != nil {
			return &file.Toolchain{
				Name:    "gcc",
				Version: match[1],
				Kind:    file.ToolchainKindCompiler,
			}
		}
	}

	return nil
}

func isGoToolchainPresent(toolchains []file.Toolchain) bool {
	for _, tc := range toolchains {
		if tc.Name == "go" {
			return true
		}
	}
	return false
}
