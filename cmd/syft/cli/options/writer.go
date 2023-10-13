package options

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/mitchellh/go-homedir"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.Writer = (*sbomMultiWriter)(nil)

var _ interface {
	io.Closer
	sbom.Writer
} = (*sbomStreamWriter)(nil)

// makeSBOMWriter creates a sbom.Writer for output or returns an error. this will either return a valid writer
// or an error but neither both and if there is no error, sbom.Writer.Close() should be called
func makeSBOMWriter(outputs []string, defaultFile string, encoders []sbom.FormatEncoder) (sbom.Writer, error) {
	outputOptions, err := parseSBOMOutputFlags(outputs, defaultFile, encoders)
	if err != nil {
		return nil, err
	}

	writer, err := newSBOMMultiWriter(outputOptions...)
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// parseSBOMOutputFlags utility to parse command-line option strings and retain the existing behavior of default format and file
func parseSBOMOutputFlags(outputs []string, defaultFile string, encoders []sbom.FormatEncoder) (out []sbomWriterDescription, errs error) {
	encoderCollection := format.NewEncoderCollection(encoders...)

	// always should have one option -- we generally get the default of "table", but just make sure
	if len(outputs) == 0 {
		outputs = append(outputs, table.ID.String())
	}

	for _, name := range outputs {
		name = strings.TrimSpace(name)

		// split to at most two parts for <format>=<file>
		parts := strings.SplitN(name, "=", 2)

		// the format name is the first part
		name = parts[0]

		// default to the --file or empty string if not specified
		file := defaultFile

		// If a file is specified as part of the output formatName, use that
		if len(parts) > 1 {
			file = parts[1]
		}

		enc := encoderCollection.GetByString(name)
		if enc == nil {
			errs = multierror.Append(errs, fmt.Errorf(`unsupported output format "%s", supported formats are: %+v`, name, formatVersionOptions(encoderCollection.NameVersions())))
			continue
		}

		out = append(out, newSBOMWriterDescription(enc, file))
	}
	return out, errs
}

// formatVersionOptions takes a list like ["github-json", "syft-json@11.0.0", "cyclonedx-xml@1.0", "cyclondx-xml@1.1"...]
// and formats it into a human-readable string like:
//
// Available formats:
//   - cyclonedx-json @ 1.2, 1.3, 1.4, 1.5
//   - cyclonedx-xml @ 1.0, 1.1, 1.2, 1.3, 1.4, 1.5
//   - github-json
//   - spdx-json @ 2.2, 2.3
//   - spdx-tag-value @ 2.1, 2.2, 2.3
//   - syft-json
//   - syft-table
//   - syft-text
//   - template
func formatVersionOptions(nameVersionPairs []string) string {
	availableVersions := make(map[string][]string)
	availableFormats := strset.New()
	for _, nameVersion := range nameVersionPairs {
		fields := strings.SplitN(nameVersion, "@", 2)
		if len(fields) == 2 {
			availableVersions[fields[0]] = append(availableVersions[fields[0]], fields[1])
		}
		availableFormats.Add(fields[0])
	}

	// find any formats with exactly one version -- remove them from the version map
	for name, versions := range availableVersions {
		if len(versions) == 1 {
			delete(availableVersions, name)
		}
	}

	sortedAvailableFormats := availableFormats.List()
	sort.Strings(sortedAvailableFormats)

	var s strings.Builder

	s.WriteString("\n")
	s.WriteString("Available formats:")

	for _, name := range sortedAvailableFormats {
		s.WriteString("\n")

		s.WriteString(fmt.Sprintf("   - %s", name))

		if len(availableVersions[name]) > 0 {
			s.WriteString(" @ ")
			s.WriteString(strings.Join(availableVersions[name], ", "))
		}
	}

	return s.String()
}

// sbomWriterDescription Format and path strings used to create sbom.Writer
type sbomWriterDescription struct {
	Format sbom.FormatEncoder
	Path   string
}

func newSBOMWriterDescription(f sbom.FormatEncoder, p string) sbomWriterDescription {
	expandedPath, err := homedir.Expand(p)
	if err != nil {
		log.Warnf("could not expand given writer output path=%q: %w", p, err)
		// ignore errors
		expandedPath = p
	}
	return sbomWriterDescription{
		Format: f,
		Path:   expandedPath,
	}
}

// sbomMultiWriter holds a list of child sbom.Writers to apply all Write and Close operations to
type sbomMultiWriter struct {
	writers []sbom.Writer
}

// newSBOMMultiWriter create all report writers from input options; if a file is not specified the given defaultWriter is used
func newSBOMMultiWriter(options ...sbomWriterDescription) (_ *sbomMultiWriter, err error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &sbomMultiWriter{}

	for _, option := range options {
		switch len(option.Path) {
		case 0:
			out.writers = append(out.writers, &sbomPublisher{
				format: option.Format,
			})
		default:
			// create any missing subdirectories
			dir := path.Dir(option.Path)
			if dir != "" {
				s, err := os.Stat(dir)
				if err != nil {
					err = os.MkdirAll(dir, 0755) // maybe should be os.ModePerm ?
					if err != nil {
						return nil, err
					}
				} else if !s.IsDir() {
					return nil, fmt.Errorf("output path does not contain a valid directory: %s", option.Path)
				}
			}
			fileOut, err := os.OpenFile(option.Path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return nil, fmt.Errorf("unable to create report file: %w", err)
			}
			out.writers = append(out.writers, &sbomStreamWriter{
				format: option.Format,
				out:    fileOut,
			})
		}
	}

	return out, nil
}

// Write writes the SBOM to all writers
func (m *sbomMultiWriter) Write(s sbom.SBOM) (errs error) {
	for _, w := range m.writers {
		err := w.Write(s)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("unable to write SBOM: %w", err))
		}
	}
	return errs
}

// sbomStreamWriter implements sbom.Writer for a given format and io.Writer, also providing a close function for cleanup
type sbomStreamWriter struct {
	format sbom.FormatEncoder
	out    io.Writer
}

// Write the provided SBOM to the data stream
func (w *sbomStreamWriter) Write(s sbom.SBOM) error {
	defer w.Close()
	return w.format.Encode(w.out, s)
}

// Close any resources, such as open files
func (w *sbomStreamWriter) Close() error {
	if closer, ok := w.out.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// sbomPublisher implements sbom.Writer that publishes results to the event bus
type sbomPublisher struct {
	format sbom.FormatEncoder
}

// Write the provided SBOM to the data stream
func (w *sbomPublisher) Write(s sbom.SBOM) error {
	buf := &bytes.Buffer{}
	if err := w.format.Encode(buf, s); err != nil {
		return fmt.Errorf("unable to encode SBOM: %w", err)
	}

	bus.Report(buf.String())
	return nil
}
