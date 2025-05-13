package spdxtagvalue

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/spdx/tools-golang/tagvalue"

	"github.com/anchore/syft/syft/format/common/spdxhelpers"
	"github.com/anchore/syft/syft/format/internal/stream"
	"github.com/anchore/syft/syft/sbom"
)

var _ sbom.FormatDecoder = (*decoder)(nil)

type decoder struct {
}

func NewFormatDecoder() sbom.FormatDecoder {
	return decoder{}
}

func (d decoder) Decode(r io.Reader) (*sbom.SBOM, sbom.FormatID, string, error) {
	reader, err := stream.SeekableReader(r)
	if err != nil {
		return nil, "", "", err
	}

	// since spdx lib will always return the latest version of the document, we need to identify the version
	// first and then decode into the appropriate document object. Otherwise if we get the version info from the
	// decoded object we will always get the latest version (instead of the version we decoded from).
	id, version := d.Identify(reader)
	if id != ID {
		return nil, "", "", fmt.Errorf("not a spdx tag-value document")
	}
	if version == "" {
		return nil, "", "", fmt.Errorf("unsupported spdx tag-value document version")
	}

	if _, err = reader.Seek(0, io.SeekStart); err != nil {
		return nil, "", "", fmt.Errorf("unable to seek to start of SPDX Tag-Value SBOM: %w", err)
	}

	doc, err := tagvalue.Read(reader)
	if err != nil {
		return nil, id, version, fmt.Errorf("unable to decode spdx tag-value: %w", err)
	}

	s, err := spdxhelpers.ToSyftModel(doc)
	if err != nil {
		return nil, id, version, err
	}
	return s, id, version, nil
}

func (d decoder) Identify(r io.Reader) (sbom.FormatID, string) {
	if r == nil {
		return "", ""
	}

	// Example document
	// SPDXVersion: SPDX-2.3
	// DataLicense: CC0-1.0
	// SPDXID: SPDXRef-DOCUMENT

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	var id sbom.FormatID
	var version string
	for i := 0; scanner.Scan() && i < 3; i++ {
		line := scanner.Text()
		if strings.HasPrefix(line, "SPDXVersion:") {
			id, version = getFormatInfo(line)
			break
		}
	}

	if version == "" || id != ID {
		// not a spdx tag-value document
		return "", ""
	}

	return id, version
}

func getFormatInfo(line string) (sbom.FormatID, string) {
	// example input: SPDXVersion: SPDX-2.3
	fields := strings.SplitN(line, ":", 2)
	if len(fields) != 2 {
		return "", ""
	}
	spdxVersion := fields[1]
	if !strings.HasPrefix(strings.TrimSpace(strings.ToLower(spdxVersion)), "spdx-") {
		return "", ""
	}
	fields = strings.Split(spdxVersion, "-")
	if len(fields) != 2 {
		return ID, ""
	}

	return ID, fields[1]
}
