package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/internal/manager/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/internal/manager/internal/config"
)

func Download(appConfig config.Application) *cobra.Command {
	var imageConfigs []config.BinaryFromImage
	var urlConfigs []config.BinaryFromURL

	var skipSnippets bool

	cmd := &cobra.Command{
		Use:   "download",
		Short: "download binaries [name@version ...]",
		PreRunE: func(_ *cobra.Command, args []string) error {
			var err error
			imageConfigs, urlConfigs, err = resolveConfigs(appConfig, args, skipSnippets)
			return err
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			for _, binaryFromImageCfg := range imageConfigs {
				if err := internal.DownloadFromImage(appConfig.DownloadPath, binaryFromImageCfg); err != nil {
					return err
				}
			}

			for _, binaryFromURLCfg := range urlConfigs {
				if err := internal.DownloadFromURL(appConfig.DownloadPath, binaryFromURLCfg); err != nil {
					return err
				}
			}

			if len(imageConfigs)+len(urlConfigs) == 0 {
				fmt.Println("no binaries to download")
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&skipSnippets, "skip-if-covered-by-snippet", "s", false, "skip downloading entries already covered by snippets")

	return cmd
}

func resolveConfigs(appConfig config.Application, args []string, skipSnippets bool) ([]config.BinaryFromImage, []config.BinaryFromURL, error) {
	var imageConfigs []config.BinaryFromImage
	var urlConfigs []config.BinaryFromURL

	if len(args) > 0 {
		for _, arg := range args {
			binaryFromImageCfg := appConfig.GetBinaryFromImage(arg, "")
			if binaryFromImageCfg != nil {
				imageConfigs = append(imageConfigs, *binaryFromImageCfg)
				continue
			}
			binaryFromURLCfg := appConfig.GetBinaryFromURL(arg, "")
			if binaryFromURLCfg != nil {
				urlConfigs = append(urlConfigs, *binaryFromURLCfg)
				continue
			}
			return nil, nil, fmt.Errorf("no config found for %q", arg)
		}
	} else {
		imageConfigs = appConfig.FromImages
		urlConfigs = appConfig.FromURLs
	}

	if skipSnippets {
		var err error
		imageConfigs, err = configsWithoutSnippets(appConfig, imageConfigs)
		if err != nil {
			return nil, nil, err
		}
		urlConfigs, err = urlConfigsWithoutSnippets(appConfig, urlConfigs)
		if err != nil {
			return nil, nil, err
		}
	}

	return imageConfigs, urlConfigs, nil
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

func urlConfigsWithoutSnippets(appConfig config.Application, configs []config.BinaryFromURL) ([]config.BinaryFromURL, error) {
	entries, err := internal.ListAllEntries(appConfig)
	if err != nil {
		return nil, err
	}

	var filtered []config.BinaryFromURL

	for _, cfg := range configs {
		if entries.BinaryFromURLHasSnippet(cfg) {
			continue
		}
		filtered = append(filtered, cfg)
	}

	return filtered, nil
}
