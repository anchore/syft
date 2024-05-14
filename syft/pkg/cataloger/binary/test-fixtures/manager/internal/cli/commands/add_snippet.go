package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/anmitsu/go-shlex"
	"github.com/spf13/cobra"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/ui"
)

func AddSnippet(appConfig config.Application) *cobra.Command {
	var binaryPath, searchPattern string
	var length, prefixLength int

	cmd := &cobra.Command{
		Use:   "add-snippet",
		Short: "capture snippets from binaries",
		Args:  cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			candidates, err := internal.ListAllBinaries(appConfig)
			if err != nil {
				return fmt.Errorf("unable to list binaries: %w", err)
			}

			// launch the UI to pick a path
			var binaryPaths []string
			for _, k := range internal.NewLogicalEntryKeys(candidates) {
				info := candidates[k]
				if info.BinaryPath != "" {
					binaryPaths = append(binaryPaths, info.BinaryPath)
				}
			}

			binaryPath, err = ui.PromptSelectBinary(binaryPaths)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			name, version, _, err := inferInfoFromBinaryPath(appConfig, binaryPath)
			if err != nil {
				return fmt.Errorf("unable to infer name and version from binary path: %w", err)
			}

			if searchPattern == "" {
				searchPattern = strings.ReplaceAll(version, ".", `\\.`)
			}

			return runAddSnippet(binaryPath, name, version, searchPattern, length, prefixLength)
		},
	}

	cmd.Flags().StringVar(&searchPattern, "search-for", "", "the pattern to search for in the binary (defaults to the version)")
	cmd.Flags().IntVar(&length, "length", 100, "the length of the snippet to capture")
	cmd.Flags().IntVar(&prefixLength, "prefix-length", 20, "number of bytes before the search hit to capture")

	return cmd
}

func runAddSnippet(binaryPath, name, version, searchPattern string, length, prefixLength int) error {
	// invoke ./capture-snippet.sh <path-to-binary> <version> [--search-for <pattern>] [--length <length>] [--prefix-length <prefix_length>]"

	cmd := exec.Command("./capture-snippet.sh", binaryPath, version)

	var args []string
	if searchPattern != "" {
		args = append(args, "--search-for", searchPattern)
	}
	if name != "" {
		args = append(args, "--group", name)
	}
	if length > 0 {
		args = append(args, fmt.Sprintf("--length %d", length))
	}
	if prefixLength > 0 {
		args = append(args, fmt.Sprintf("--prefix-length %d", prefixLength))
	}

	var err error
	args, err = shlex.Split(strings.Join(args, " "), true)
	if err != nil {
		return fmt.Errorf("failed to parse arguments: %w", err)
	}
	cmd.Args = append(cmd.Args, args...)

	fmt.Printf("running: %s\n", strings.Join(cmd.Args, " "))

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("command execution failed: %w", err)
	}

	return nil
}
