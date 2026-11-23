package internal

import (
	"slices"
	"strings"

	"github.com/anchore/syft/syft/file"
)

// ArchiveEntries splits coordinates into those not within an archive and, for each archive, the files
// directly within it, each sorted. An archive not among coordinates is added, so every file within an
// archive has its archive to be described under.
func ArchiveEntries(coordinates []file.Coordinates, sorter func(a, b file.Coordinates) int) (top []file.Coordinates, entries map[file.Coordinates][]file.Coordinates) {
	present := file.NewCoordinateSet(coordinates...)
	entries = map[file.Coordinates][]file.Coordinates{}
	for _, c := range coordinates {
		for {
			// RealPath is cut off first, so a "!/" in it is not taken for an archive boundary
			rest, ok := strings.CutPrefix(c.FullPath, c.RealPath)
			if !ok || !strings.HasPrefix(rest, file.ArchivePathSeparator) {
				top = append(top, c)
				break
			}
			archive := file.Coordinates{RealPath: c.RealPath, FileSystemID: c.FileSystemID}
			if i := strings.LastIndex(rest, file.ArchivePathSeparator); i > 0 {
				archive.FullPath = c.FullPath[:len(c.RealPath)+i]
			}
			entries[archive] = append(entries[archive], c)
			if present.Contains(archive) {
				break
			}
			present.Add(archive)
			c = archive
		}
	}
	slices.SortFunc(top, sorter)
	for _, e := range entries {
		slices.SortFunc(e, sorter)
	}
	return top, entries
}
