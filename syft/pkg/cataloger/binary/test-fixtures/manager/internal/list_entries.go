package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
)

type Entries map[LogicalEntryKey]EntryInfo

type EntryInfo struct {
	IsConfigured bool
	BinaryPath   string
	SnippetPath  string
}

type LogicalEntryKey struct {
	OrgName  string
	Version  string
	Platform string
	Filename string
}

func (k LogicalEntryKey) Path() string {
	return fmt.Sprintf("%s/%s/%s/%s", k.OrgName, k.Version, k.Platform, k.Filename)
}

type LogicalEntryKeys []LogicalEntryKey

func (l LogicalEntryKeys) Len() int {
	return len(l)
}

func (l LogicalEntryKeys) Less(i, j int) bool {
	if l[i].OrgName == l[j].OrgName {
		if l[i].Version == l[j].Version {
			if l[i].Platform == l[j].Platform {
				return l[i].Filename < l[j].Filename
			}
			return l[i].Platform < l[j].Platform
		}
		return l[i].Version < l[j].Version
	}
	return l[i].OrgName < l[j].OrgName
}

func (l LogicalEntryKeys) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func NewLogicalEntryKeys(m map[LogicalEntryKey]EntryInfo) LogicalEntryKeys {
	var keys LogicalEntryKeys
	for k := range m {
		keys = append(keys, k)
	}
	sort.Sort(keys)
	return keys
}

func ListAllBinaries(appConfig config.Application) (Entries, error) {
	binaries, err := allFilePaths(appConfig.DownloadPath)
	if err != nil {
		return nil, fmt.Errorf("unable to list binaries: %w", err)
	}

	cases := make(map[LogicalEntryKey]EntryInfo)
	for _, storePath := range binaries {
		isConfigured := appConfig.GetBinaryFromImageByPath(storePath) != nil

		relativePath, err := filepath.Rel(appConfig.DownloadPath, storePath)
		if err != nil {
			return nil, fmt.Errorf("unable to get relative path for %q: %w", storePath, err)
		}

		key, err := getLogicalKey(relativePath)
		if err != nil {
			return nil, fmt.Errorf("unable to get logical key for binary %q: %w", storePath, err)
		}
		cases[*key] = EntryInfo{
			IsConfigured: isConfigured,
			BinaryPath:   storePath,
		}
	}

	return cases, nil
}

func ListAllEntries(appConfig config.Application) (Entries, error) {
	snippets, err := allFilePaths(appConfig.SnippetPath)
	if err != nil {
		return nil, fmt.Errorf("unable to list snippets: %w", err)
	}

	cases, err := ListAllBinaries(appConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to list binaries: %w", err)
	}

	// anything configured that isn't in the binaries list?
	for _, cfg := range appConfig.FromImages {
		for _, image := range cfg.Images {
			for _, path := range cfg.AllStorePathsForImage(image, appConfig.DownloadPath) {
				key := newLogicalEntryForImage(cfg, image, path)
				if _, ok := cases[key]; ok {
					continue
				}
				cases[key] = EntryInfo{
					IsConfigured: true,
				}
			}
		}
	}

	// correlate snippets to existing binaries and configurations (and add unmanaged ones)
	for _, storePath := range snippets {
		relativePath, err := filepath.Rel(appConfig.SnippetPath, storePath)
		if err != nil {
			return nil, fmt.Errorf("unable to get relative path for %q: %w", storePath, err)
		}
		key, err := getLogicalKey(relativePath)
		if err != nil {
			return nil, fmt.Errorf("unable to get logical key for snippet %q: %w", storePath, err)
		}

		if v, ok := cases[*key]; ok {
			v.SnippetPath = storePath
			cases[*key] = v

			continue
		}

		cases[*key] = EntryInfo{
			IsConfigured: false,
			SnippetPath:  storePath,
		}
	}

	return cases, nil
}

func newLogicalEntryForImage(cfg config.BinaryFromImage, image config.Image, storePath string) LogicalEntryKey {
	return LogicalEntryKey{
		OrgName:  cfg.Name(),
		Version:  cfg.Version,
		Platform: config.PlatformAsValue(image.Platform),
		Filename: filepath.Base(storePath),
	}
}

func getLogicalKey(managedBinaryPath string) (*LogicalEntryKey, error) {
	// infer the logical key from the path alone: name/version/platform/filename

	items := SplitFilepath(managedBinaryPath)
	if len(items) < 4 {
		return nil, fmt.Errorf("invalid managed binary path: %q", managedBinaryPath)
	}

	return &LogicalEntryKey{
		OrgName:  items[0],
		Version:  items[1],
		Platform: items[2],
		Filename: filepath.Join(items[3:]...),
	}, nil
}

func allFilePaths(root string) ([]string, error) {
	var paths []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() && !strings.HasSuffix(path, digestFileSuffix) {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func (e Entries) BinaryFromImageHasSnippet(cfg config.BinaryFromImage) bool {
	// all paths for all images must have snippets to return true
	for _, image := range cfg.Images {
		for _, storePath := range cfg.AllStorePathsForImage(image, "") {
			key := newLogicalEntryForImage(cfg, image, storePath)
			if v, ok := e[key]; ok {
				if v.SnippetPath == "" {
					return false
				}
			}
		}
	}
	return true
}
