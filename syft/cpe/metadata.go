package cpe

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"time"

	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/spf13/afero"
)

const MetadataFileName = "cpe-dictionary-metadata.json"

type Metadata struct {
	Date     time.Time `json:"lastModifiedDate"`
	Checksum string    `json:"sha256"`
	Count    uint64    `json:"count"`
}

func metadataPath(dir string) string {
	return path.Join(dir, MetadataFileName)
}

func (m *Metadata) toIndexName() string {
	parts := strings.SplitN(m.Checksum, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return parts[0]
}

// NewMetadataFromFile loads a Listing from a given filepath.
func NewMetadataFromFile(fs afero.Fs, path string) (Metadata, error) {
	f, err := fs.Open(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("unable to open CPE dictionary meta path: %w", err)
	}
	defer f.Close()

	var metadata Metadata
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}

		key := fields[0]
		value := strings.TrimSpace(fields[1])

		switch key {
		case "lastModifiedDate":
			metadata.Date, _ = time.Parse(time.RFC3339, value)
		case "sha256":
			metadata.Checksum = "sha256:" + strings.ToLower(value)
		}
	}

	return metadata, nil
}

// NewMetadataFromDir generates a Metadata object from a directory containing a cpe-dictionary json & bleve index.
func NewMetadataFromDir(fs afero.Fs, dir string) (*Metadata, error) {
	metadataFilePath := metadataPath(dir)
	if !file.Exists(fs, metadataFilePath) {
		return nil, nil
	}
	f, err := fs.Open(metadataFilePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open CPE dictionary metadata path (%s): %w", metadataFilePath, err)
	}
	defer f.Close()

	var m Metadata
	err = json.NewDecoder(f).Decode(&m)
	if err != nil {
		return nil, fmt.Errorf("unable to parse CPE dictionary metadata (%s): %w", metadataFilePath, err)
	}
	return &m, nil
}

// IsSupersededBy takes another Metadata and determines if the entry candidate is newer than what is hinted at
// in the current Metadata object.
func (m *Metadata) IsSupersededBy(entry *Metadata) bool {
	if m == nil {
		log.Debugf("cannot find existing metadata, using update...")
		// any valid update beats no database, use it!
		return true
	}

	if entry.Date.After(m.Date) {
		log.Debugf("existing database (%s) is older than candidate update (%s), using update...", m.Date.String(), entry.Date.String())
		// the listing is newer than the existing db, use it!
		return true
	}

	log.Debugf("existing database is already up to date")
	return false
}

// Write out a Metadata object to the given path.
func (m Metadata) Write(toPath string) error {
	contents, err := json.MarshalIndent(&m, "", " ")
	if err != nil {
		return fmt.Errorf("failed to encode metadata file: %w", err)
	}

	err = ioutil.WriteFile(toPath, contents, 0600)
	if err != nil {
		return fmt.Errorf("failed to write metadata file: %w", err)
	}
	return nil
}
