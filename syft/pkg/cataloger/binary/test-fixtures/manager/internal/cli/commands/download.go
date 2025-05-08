package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

func Download(appConfig config.Application) *cobra.Command {
	var configs []config.BinaryFromImage

	var skipSnippets bool

	cmd := &cobra.Command{
		Use:   "download",
		Short: "download binaries [name@version ...]",
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				for _, arg := range args {
					binaryFromImageCfg := appConfig.GetBinaryFromImage(arg, "")
					if binaryFromImageCfg == nil {
						return fmt.Errorf("no config found for %q", arg)
					}
					configs = append(configs, *binaryFromImageCfg)
				}
			} else {
				configs = appConfig.FromImages
			}

			if skipSnippets {
				var err error
				configs, err = configsWithoutSnippets(appConfig, configs)
				if err != nil {
					return err
				}
			}

			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			for _, binaryFromImageCfg := range configs {
				if err := internal.DownloadFromImage(appConfig.DownloadPath, binaryFromImageCfg); err != nil {
					return err
				}
			}

			if len(configs) == 0 {
				fmt.Println("no binaries to download")
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&skipSnippets, "skip-if-covered-by-snippet", "s", false, "skip downloading entries already covered by snippets")

	return cmd
}

func configsWithoutSnippets(appConfig config.Application, configs []config.BinaryFromImage) ([]config.BinaryFromImage, error) {
	entries, err := internal.ListAllEntries(appConfig)
	if err != nil {
		return nil, err
	}

	var filtered []config.BinaryFromImage

	for _, cfg := range configs {
		if entries.BinaryFromImageHasSnippet(cfg) {
			continue
		}
		filtered = append(filtered, cfg)
	}

	return filtered, nil
}
