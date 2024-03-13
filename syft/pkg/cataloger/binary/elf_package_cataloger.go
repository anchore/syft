package binary

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/mimetype"
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
	Location                            file.Location `json:"-"`
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

func (c *elfPackageCataloger) Catalog(_ context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	locations, err := resolver.FilesByMIMEType(mimetype.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get binary files by mime type: %w", err)
	}

	// first find all ELF binaries that have notes
	var notesByLocation = make(map[elfPackageKey][]elfBinaryPackageNotes)
	for _, location := range locations {
		reader, err := resolver.FileContentsByLocation(location)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get binary contents %q: %w", location.Path(), err)
		}

		notes, err := c.parseElfNotes(file.LocationReadCloser{
			Location:   location,
			ReadCloser: reader,
		})
		if err != nil {
			log.WithFields("file", location.Path(), "error", err).Trace("unable to parse ELF notes")
			continue
		}

		if notes == nil {
			continue
		}

		notes.Location = location
		key := elfPackageKey{
			Name:    notes.Name,
			Version: notes.Version,
			PURL:    notes.PURL,
			CPE:     notes.CPE,
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
		pkgs = append(pkgs, newELFPackage(notes[0], noteLocations, nil))
	}

	// why not return relationships? We have an executable cataloger that will note the dynamic libraries imported by
	// each binary. After all files and packages are processed there is a final task that creates package-to-package
	// and package-to-file relationships based on the dynamic libraries imported by each binary.
	return pkgs, nil, nil
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

	var metadata elfBinaryPackageNotes
	if err := json.Unmarshal(notes, &metadata); err != nil {
		log.WithFields("file", r.Location.Path(), "error", err).Trace("unable to unmarshal ELF package notes as JSON")
		return nil, nil
	}

	return &metadata, err
}
