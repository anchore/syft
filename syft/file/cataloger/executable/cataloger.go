package executable

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/dustin/go-humanize"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
)

type Config struct {
	MIMETypes []string `json:"mime-types" yaml:"mime-types" mapstructure:"mime-types"`
	Globs     []string `json:"globs" yaml:"globs" mapstructure:"globs"`
}

type Cataloger struct {
	config Config
}

func DefaultConfig() Config {
	m := mimetype.ExecutableMIMETypeSet.List()
	sort.Strings(m)
	return Config{
		MIMETypes: m,
		Globs:     nil,
	}
}

func NewCataloger(cfg Config) *Cataloger {
	return &Cataloger{
		config: cfg,
	}
}

func (i *Cataloger) Catalog(resolver file.Resolver) (map[file.Coordinates]file.Executable, error) {
	locs, err := resolver.FilesByMIMEType(i.config.MIMETypes...)
	if err != nil {
		return nil, fmt.Errorf("unable to get file locations for binaries: %w", err)
	}

	locs, err = filterByGlobs(locs, i.config.Globs)
	if err != nil {
		return nil, err
	}

	prog := catalogingProgress(int64(len(locs)))

	results := make(map[file.Coordinates]file.Executable)
	for _, loc := range locs {
		prog.AtomicStage.Set(loc.Path())

		reader, err := resolver.FileContentsByLocation(loc)
		if err != nil {
			// TODO: known-unknowns
			log.WithFields("error", err).Warnf("unable to get file contents for %q", loc.RealPath)
			continue
		}
		exec, err := processExecutable(loc, reader.(unionreader.UnionReader))
		if err != nil {
			log.WithFields("error", err).Warnf("unable to process executable %q", loc.RealPath)
		}
		if exec != nil {
			prog.Increment()
			results[loc.Coordinates] = *exec
		}
	}

	log.Debugf("executable cataloger processed %d files", len(results))

	prog.AtomicStage.Set(fmt.Sprintf("%s executables", humanize.Comma(prog.Current())))
	prog.SetCompleted()

	return results, nil
}

func catalogingProgress(locations int64) *monitor.CatalogerTaskProgress {
	info := monitor.GenericTask{
		Title: monitor.Title{
			Default: "Executables",
		},
		ParentID: monitor.TopLevelCatalogingTaskID,
	}

	return bus.StartCatalogerTask(info, locations, "")
}

func filterByGlobs(locs []file.Location, globs []string) ([]file.Location, error) {
	if len(globs) == 0 {
		return locs, nil
	}
	var filteredLocs []file.Location
	for _, loc := range locs {
		matches, err := locationMatchesGlob(loc, globs)
		if err != nil {
			return nil, err
		}
		if matches {
			filteredLocs = append(filteredLocs, loc)
		}
	}
	return filteredLocs, nil
}

func locationMatchesGlob(loc file.Location, globs []string) (bool, error) {
	for _, glob := range globs {
		for _, path := range []string{loc.RealPath, loc.AccessPath} {
			if path == "" {
				continue
			}
			matches, err := doublestar.Match(glob, path)
			if err != nil {
				return false, fmt.Errorf("unable to match glob %q to path %q: %w", glob, path, err)
			}
			if matches {
				return true, nil
			}
		}
	}
	return false, nil
}

func processExecutable(loc file.Location, reader unionreader.UnionReader) (*file.Executable, error) {
	data := file.Executable{}

	// determine the executable format

	format, err := findExecutableFormat(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to determine executable kind: %w", err)
	}

	if format == "" {
		log.Debugf("unable to determine executable format for %q", loc.RealPath)
		return nil, nil
	}

	data.Format = format

	securityFeatures, err := findSecurityFeatures(format, reader)
	if err != nil {
		log.WithFields("error", err).Warnf("unable to determine security features for %q", loc.RealPath)
		return nil, nil
	}

	data.SecurityFeatures = securityFeatures

	return &data, nil
}

func findExecutableFormat(reader unionreader.UnionReader) (file.ExecutableFormat, error) {
	// read the first sector of the file
	buf := make([]byte, 512)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		return "", fmt.Errorf("unable to read first sector of file: %w", err)
	}
	if n < 512 {
		return "", fmt.Errorf("unable to read enough bytes to determine executable format")
	}

	switch {
	case isMacho(buf):
		return file.MachO, nil
	case isPE(buf):
		return file.PE, nil
	case isELF(buf):
		return file.ELF, nil
	}

	return "", nil
}

func isMacho(by []byte) bool {
	// sourced from https://github.com/gabriel-vasile/mimetype/blob/02af149c0dfd1444d9256fc33c2012bb3153e1d2/internal/magic/binary.go#L44

	if classOrMachOFat(by) && by[7] < 20 {
		return true
	}

	if len(by) < 4 {
		return false
	}

	be := binary.BigEndian.Uint32(by)
	le := binary.LittleEndian.Uint32(by)

	return be == macho.Magic32 ||
		le == macho.Magic32 ||
		be == macho.Magic64 ||
		le == macho.Magic64
}

// Java bytecode and Mach-O binaries share the same magic number.
// More info here https://github.com/threatstack/libmagic/blob/master/magic/Magdir/cafebabe
func classOrMachOFat(in []byte) bool {
	// sourced from https://github.com/gabriel-vasile/mimetype/blob/02af149c0dfd1444d9256fc33c2012bb3153e1d2/internal/magic/binary.go#L44

	// There should be at least 8 bytes for both of them because the only way to
	// quickly distinguish them is by comparing byte at position 7
	if len(in) < 8 {
		return false
	}

	return bytes.HasPrefix(in, []byte{0xCA, 0xFE, 0xBA, 0xBE})
}

func isPE(by []byte) bool {
	return bytes.HasPrefix(by, []byte("MZ"))
}

func isELF(by []byte) bool {
	return bytes.HasPrefix(by, []byte(elf.ELFMAG))
}

func findSecurityFeatures(format file.ExecutableFormat, reader unionreader.UnionReader) (*file.ELFSecurityFeatures, error) {
	// TODO: add support for PE and MachO
	switch format { //nolint: gocritic
	case file.ELF:
		return findELFSecurityFeatures(reader) //nolint: gocritic
		// case file.PE:
		//	return findPESecurityFeatures(reader)
		// case file.MachO:
		//	return findMachOSecurityFeatures(reader)
	}
	return nil, fmt.Errorf("unsupported executable format: %q", format)
}
