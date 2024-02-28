package commands

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

func WriteSnippet(appConfig config.Application) *cobra.Command {
	var offset, length int
	var name, version string
	var binaryPath string

	cmd := &cobra.Command{
		Use:   "write-snippet [binary]",
		Short: "capture snippets from binaries",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 && (name != "" || version != "") {
				return fmt.Errorf("cannot provide name or version without a binary path")
			}

			binaryPath = args[0]
			if _, err := os.Stat(binaryPath); err != nil {
				return fmt.Errorf("unable to stat %q: %w", binaryPath, err)
			}

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			platform, err := getPlatform(binaryPath)
			if err != nil {
				return fmt.Errorf("unable to get platform: %w", err)
			}

			snippetPath, err := getSnippetPath(appConfig, binaryPath, name, version, platform)
			if err != nil {
				return fmt.Errorf("unable to get snippet path: %w", err)
			}

			return runWriteSnippet(binaryPath, offset, length, snippetPath)
		},
	}

	cmd.Flags().IntVar(&offset, "offset", -1, "the offset in the binary to start the snippet")
	cmd.Flags().IntVar(&length, "length", 100, "the length of the snippet to capture")
	cmd.Flags().StringVar(&name, "name", "", "the name of the snippet")
	cmd.Flags().StringVar(&version, "version", "", "the version of the snippet")

	return cmd
}

func runWriteSnippet(binaryPath string, offset, length int, snippetPath string) error {
	f, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("unable to open binary %q: %w", binaryPath, err)
	}

	n, err := f.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return fmt.Errorf("unable to seek to offset %d: %w", offset, err)
	}

	if n != int64(offset) {
		return fmt.Errorf("unexpectd to seek value: %d != %d", offset, n)
	}

	buf := make([]byte, length)
	n2, err := f.Read(buf)
	if err != nil {
		return fmt.Errorf("unable to read %d bytes: %w", length, err)
	}

	if n2 != length {
		return fmt.Errorf("unexpected read length: %d != %d", length, n2)
	}

	fileDigest, err := internal.Sha256SumFile(f)
	if err != nil {
		return err
	}

	metadata := internal.SnippetMetadata{
		Name:          filepath.Base(binaryPath),
		Offset:        offset,
		Length:        length,
		SnippetSha256: internal.Sha256SumBytes(buf),
		FileSha256:    fileDigest,
	}

	metadataBytes, err := yaml.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("unable to marshal metadata: %w", err)
	}

	splitter := []byte("\n### byte snippet to follow ###\n")

	var finalBuf []byte
	finalBuf = append(finalBuf, metadataBytes...)
	finalBuf = append(finalBuf, splitter...)
	finalBuf = append(finalBuf, buf...)

	if err := os.MkdirAll(filepath.Dir(snippetPath), 0755); err != nil {
		return fmt.Errorf("unable to create destination directory: %w", err)
	}

	if err := os.WriteFile(snippetPath, finalBuf, 0600); err != nil {
		return fmt.Errorf("unable to write snippet: %w", err)
	}

	fmt.Printf("wrote snippet to %q\n", snippetPath)

	return nil
}

func getSnippetPath(appConfig config.Application, binaryPath string, name, version, platform string) (string, error) {
	binFilename := filepath.Base(binaryPath)
	platform = config.PlatformAsValue(platform)

	// if all values provided, use them
	if name != "" && version != "" && platform != "" {
		return filepath.Join(appConfig.SnippetPath, name, version, platform, binFilename), nil
	}

	// otherwise, try to infer them from the existing binary path
	name, version, platform, err := inferInfoFromBinaryPath(appConfig, binaryPath)
	if err != nil {
		return "", err
	}

	return filepath.Join(appConfig.SnippetPath, name, version, platform, binFilename), nil
}

func inferInfoFromBinaryPath(appConfig config.Application, binaryPath string) (string, string, string, error) {
	relativePath, err := filepath.Rel(appConfig.DownloadPath, binaryPath)
	if err != nil {
		return "", "", "", fmt.Errorf("unable to get relative path: %w", err)
	}

	// otherwise, try to infer them from the existing binary path
	items := internal.SplitFilepath(relativePath)
	if len(items) != 4 {
		return "", "", "", fmt.Errorf("too few fields: %q", binaryPath)
	}

	name := items[0]
	version := items[1]
	platform := items[2]

	return name, version, platform, nil
}

// getPlatform will return <os>-<arch> for the given binary path, where os can be "linux", "darwin", "windows",
// and arch can be "amd64", "arm64", "arm", etc.
func getPlatform(binaryPath string) (string, error) {
	f, err := os.Open(binaryPath)
	if err != nil {
		return "", fmt.Errorf("unable to open binary %q: %w", binaryPath, err)
	}

	elfPlatform := getPlatformElf(f)
	if elfPlatform != "" {
		return elfPlatform, nil
	}

	macPlatform := getPlatformMac(f)
	if macPlatform != "" {
		return macPlatform, nil
	}

	winPlatform := getPlatformWindows(f)
	if winPlatform != "" {
		return winPlatform, nil
	}

	// attempt to infer from the path. It is possible to see invalid-looking binaries that are still something
	// we'd like to detect.
	items := internal.SplitFilepath(binaryPath)
	if len(items) > 2 {
		candidate := items[len(items)-2]
		if strings.Contains(candidate, "linux") || strings.Contains(candidate, "darwin") || strings.Contains(candidate, "windows") {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("unable to determine platform for %q", binaryPath)
}

const (
	amd64 = "amd64"
	arm64 = "arm64"
)

func getPlatformElf(f *os.File) string {
	elfFile, err := elf.NewFile(f)
	if err != nil {
		return ""
	}

	var arch string
	switch elfFile.Machine {
	case elf.EM_X86_64:
		arch = amd64
	case elf.EM_AARCH64:
		arch = arm64
	// TODO...
	default:
		arch = fmt.Sprintf("unknown-%x", elfFile.Machine)
	}

	return fmt.Sprintf("linux-%s", arch)
}

func getPlatformMac(f *os.File) string {
	machoFile, err := macho.NewFile(f)
	if err != nil {
		return ""
	}

	var arch string
	switch machoFile.Cpu {
	case macho.CpuAmd64:
		arch = amd64
	case macho.CpuArm64:
		arch = arm64
	// TODO...
	default:
		arch = fmt.Sprintf("unknown-%x", machoFile.Cpu)
	}

	return fmt.Sprintf("darwin-%s", arch)
}

func getPlatformWindows(f *os.File) string {
	peFile, err := pe.NewFile(f)
	if err != nil {
		return ""
	}

	var arch string
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		arch = amd64
	case pe.IMAGE_FILE_MACHINE_ARM64:
		arch = arm64
	// TODO...
	default:
		arch = fmt.Sprintf("unknown-%x", peFile.Machine)
	}

	return fmt.Sprintf("windows-%s", arch)
}
