package cli

import (
	"github.com/spf13/cobra"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/cli/commands"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

// list all managed binaries (in ./bin, organized by 'name-version/platform/binary')
//		manager list binaries

// list all managed snippets (in ./snippets, same organization as ./bin: 'name-version/platform/binary' where each bin is a snippet)
//		manager list snippets

// download all binaries (to ./bin)
//		manager download [--name <name>] [--version <version>]

// capture snippet from a binary identified by offset
//		manager capture snippet --binary <binary> --offset <offset> --length <length>

func New() (*cobra.Command, error) {
	cfgP, err := config.Read()
	if err != nil {
		return nil, err
	}

	cfg := *cfgP

	root := commands.Root(cfg)

	root.AddCommand(
		commands.List(cfg),
		commands.Download(cfg),
		commands.AddSnippet(cfg),
		commands.WriteSnippet(cfg),
	)

	return root, nil
}
