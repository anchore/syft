package binary

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
)

var _ pkg.Cataloger = (*elfPackageCataloger)(nil)

type elfPackageCataloger struct {
}

// TODO: for now this accounts for a single data shape from the .note.package section of an ELF binary.
// In the future, this should be generalized to support multiple data shapes, including non-json data.
// For example, fedora includes an ELF section header as a prefix to the JSON payload: https://github.com/anchore/syft/issues/2713

type elfBinaryPackageNotes struct {
	Name                                string `json:"name"`
	Version                             string `json:"version"`
	PURL                                string `json:"purl"`
	CPE                                 string `json:"cpe"`
	License                             string `json:"license"`
	pkg.ELFBinaryPackageNoteJSONPayload `json:",inline"`
	// CorrectOSCPE has the corrected casing for the osCPE field relative to the systemd ELF package metadata "spec" https://systemd.io/ELF_PACKAGE_METADATA/ .
	// Ideally in syft 2.0 this field should be replaced with the pkg.ELFBinaryPackageNoteJSONPayload.OSCPE field directly (with the struct tag corrected).
	CorrectOSCPE string        `json:"osCpe,omitempty"`
	Location     file.Location `json:"-"`
}

type elfPackageKey struct {
	Name    string
	Version string
	PURL    string
	CPE     string
}

func NewELFPackageCataloger() pkg.Cataloger {
	return &elfPackageCataloger{}
}

func (c *elfPackageCataloger) Name() string {
	return "elf-binary-package-cataloger"
}

func (c *elfPackageCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	var errs error
	locations, err := resolver.FilesByMIMEType(mimetype.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get binary files by mime type: %w", err)
	}

	// first find all ELF binaries that have notes
	var notesByLocation = make(map[elfPackageKey][]elfBinaryPackageNotes)
	for _, location := range locations {
		notes, key, err := parseElfPackageNotes(resolver, location, c)
		if err != nil {
			errs = unknown.Append(errs, location, err)
			continue
		}
		if notes == nil {
			continue
		}
		notesByLocation[key] = append(notesByLocation[key], *notes)
	}

	// now we have all ELF binaries that have notes, let's create packages for them.
	// we do this in a second pass since it is possible that we have multiple ELF binaries with the same name and version
	// which means the set of binaries collectively represent a single logical package.
	var pkgs []pkg.Package
	for _, notes := range notesByLocation {
		noteLocations := file.NewLocationSet()
		for _, note := range notes {
			noteLocations.Add(note.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		}

		// create a package for each unique name/version pair (based on the first note found)
		pkgs = append(pkgs, newELFPackage(ctx, notes[0], noteLocations))
	}

	// why not return relationships? We have an executable cataloger that will note the dynamic libraries imported by
	// each binary. After all files and packages are processed there is a final task that creates package-to-package
	// and package-to-file relationships based on the dynamic libraries imported by each binary.
	return pkgs, nil, errs
}

func parseElfPackageNotes(resolver file.Resolver, location file.Location, c *elfPackageCataloger) (*elfBinaryPackageNotes, elfPackageKey, error) {
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, elfPackageKey{}, fmt.Errorf("unable to get binary contents %q: %w", location.Path(), err)
	}
	defer internal.CloseAndLogError(reader, location.AccessPath)

	notes, err := c.parseElfNotes(file.LocationReadCloser{
		Location:   location,
		ReadCloser: reader,
	})

	if err != nil {
		log.WithFields("file", location.Path(), "error", err).Trace("unable to parse ELF notes")
		return nil, elfPackageKey{}, err
	}

	if notes == nil {
		return nil, elfPackageKey{}, nil
	}

	notes.Location = location
	key := elfPackageKey{
		Name:    notes.Name,
		Version: notes.Version,
		PURL:    notes.PURL,
		CPE:     notes.CPE,
	}
	return notes, key, nil
}

func (c *elfPackageCataloger) parseElfNotes(reader file.LocationReadCloser) (*elfBinaryPackageNotes, error) {
	metadata, err := getELFNotes(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to process ELF binary: %w", err)
	}

	if metadata == nil || metadata.Name == "" || metadata.Version == "" {
		return nil, nil
	}

	return metadata, nil
}

func getELFNotes(r file.LocationReadCloser) (*elfBinaryPackageNotes, error) {
	unionReader, err := unionreader.GetUnionReader(r)
	if err != nil {
		return nil, fmt.Errorf("unable to get union reader for binary: %w", err)
	}

	f, err := elf.NewFile(unionReader)
	if f == nil || err != nil {
		log.WithFields("file", r.Location.Path(), "error", err).Trace("unable to parse binary as ELF")
		return nil, nil
	}

	noteSection := f.Section(".note.package")
	if noteSection == nil {
		return nil, nil
	}

	notes, err := noteSection.Data()
	if err != nil {
		return nil, err
	}

	if len(notes) == 0 {
		return nil, nil
	}

	{
		var metadata *elfBinaryPackageNotes
		if metadata, err = unmarshalELFPackageNotesPayload(notes); err == nil {
			return metadata, nil
		}
	}

	{
		var header elf64SectionHeader
		headerSize := binary.Size(header) / 4
		if len(notes) > headerSize {
			var metadata *elfBinaryPackageNotes
			newPayload := bytes.TrimRight(notes[headerSize:], "\x00")
			if metadata, err = unmarshalELFPackageNotesPayload(newPayload); err == nil {
				return metadata, nil
			}
			log.WithFields("file", r.Location.Path(), "error", err).Trace("unable to unmarshal ELF package notes as JSON")
		}
	}

	return nil, err
}

func unmarshalELFPackageNotesPayload(data []byte) (*elfBinaryPackageNotes, error) {
	var metadata elfBinaryPackageNotes
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unable to unmarshal ELF package notes payload: %w", err)
	}

	// normalize the os CPE field
	if metadata.OSCPE == "" { //nolint:staticcheck
		// ensure the public field is populated for backwards compatibility
		metadata.OSCPE = metadata.CorrectOSCPE //nolint:staticcheck
	}

	return &metadata, nil
}

type elf64SectionHeader struct {
	ShName      uint32
	ShType      uint32
	ShFlags     uint64
	ShAddr      uint64
	ShOffset    uint64
	ShSize      uint64
	ShLink      uint32
	ShInfo      uint32
	ShAddralign uint64
	ShEntsize   uint64
}
