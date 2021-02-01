package cpe

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/facebookincubator/nvdtools/cpedict"
	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/blevesearch/bleve/v2"
	"github.com/hashicorp/go-getter"
	"github.com/spf13/afero"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

const MetaName = "official-cpe-dictionary_v2.3.meta"
const FileName = "official-cpe-dictionary_v2.3.xml"

type Curator struct {
	fs         afero.Fs
	config     config.CPEDictionary
	downloader file.Getter
}

type CPE struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

// Type give the document type to used for indexing
func (CPE) Type() string {
	return "cpe"
}

func NewCurator(cfg config.CPEDictionary) Curator {
	return Curator{
		config:     cfg,
		fs:         afero.NewOsFs(),
		downloader: file.NewGetter(),
	}
}

func (c *Curator) GetDictionary() (Dictionary, error) {
	_, err := c.Validate()
	if err != nil {
		return nil, fmt.Errorf("CPE dictionary is corrupt (run cpe update to correct): %+v", err)
	}

	metadata, _ := NewMetadataFromDir(c.fs, c.config.CacheDir)
	indexPath := path.Join(c.config.CacheDir, metadata.toIndexName())
	index, err := bleve.Open(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CPE dictionary index (run cpe update to correct): %+v", err)
	}

	return NewBleveDictionary(index, c.config), nil
}

func (c *Curator) Status() Status {
	metadata, err := NewMetadataFromDir(c.fs, c.config.CacheDir)
	if err != nil {
		return Status{
			Err: fmt.Errorf("failed to parse CPE dictionary metadata (%s): %w", c.config.CacheDir, err),
		}
	}
	if metadata == nil {
		return Status{
			Err: fmt.Errorf("database metadata not found at %q", c.config.CacheDir),
		}
	}

	count, err := c.Validate()

	return Status{
		Location: c.config.CacheDir,
		Date:     metadata.Date,
		Entries:  count,
		Err:      err,
	}
}

func (c *Curator) Delete() error {
	return c.fs.RemoveAll(c.config.CacheDir)
}

func (c *Curator) Update() (bool, error) {
	// let consumers know of a monitorable event (download + import stages)
	importProgress := &progress.Manual{
		Total: 1,
	}
	stage := &progress.Stage{
		Current: "checking for update",
	}
	downloadProgress := &progress.Manual{
		Total: 1,
	}
	aggregateProgress := progress.NewAggregator(progress.DefaultStrategy, downloadProgress, importProgress)

	bus.Publish(partybus.Event{
		Type: event.UpdateCPEDictionary,
		Value: progress.StagedProgressable(&struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: progress.Progressable(aggregateProgress),
		}),
	})

	defer downloadProgress.SetCompleted()
	defer importProgress.SetCompleted()

	updateAvailable, metadata, err := c.IsUpdateAvailable()
	if err != nil {
		// we want to continue if possible even if we can't check for an update
		log.Infof("unable to check for CPE dictionary update")
		log.Debugf("check for CPE dictionary update failed: %+v", err)
	}
	if updateAvailable {
		log.Infof("Downloading new CPE dictionary")
		err = c.UpdateTo(metadata, downloadProgress, importProgress, stage)
		if err != nil {
			return false, fmt.Errorf("unable to update CPE dictionary: %w", err)
		}
		log.Infof("Updated CPE dictionary to date=%q", metadata.Date)
		return true, nil
	}
	stage.Current = "up to date"
	return false, nil
}

func (c *Curator) IsUpdateAvailable() (bool, *Metadata, error) {
	log.Debugf("checking for available CPE dictionary updates")

	update, err := c.NewMetadataFromURL(c.fs, c.config.UpdateURL)
	if err != nil {
		return false, nil, fmt.Errorf("unable to parse CPE dictionary meta content: %w", err)
	}

	// compare created data to current db date
	current, err := NewMetadataFromDir(c.fs, c.config.CacheDir)
	if err != nil {
		return false, nil, fmt.Errorf("current CPE dictionary metadata corrupt: %w", err)
	}

	if current.IsSupersededBy(update) {
		log.Debugf("CPE dictionary update available: %s", update)
		return true, update, nil
	}
	log.Debugf("no CPE dictionary update available")

	return false, nil, nil
}

// NewMetadataFromURL loads a meta file from a URL.
func (c *Curator) NewMetadataFromURL(fs afero.Fs, updateURL string) (*Metadata, error) {
	tempFile, err := afero.TempFile(c.fs, "", MetaName)
	if err != nil {
		return &Metadata{}, fmt.Errorf("unable to create CPE dictionary temp file: %w", err)
	}

	metaURL := strings.TrimSuffix(updateURL, ".xml.gz") + ".meta"
	err = getter.GetFile(tempFile.Name(), metaURL)
	if err != nil {
		return &Metadata{}, fmt.Errorf("unable to download CPE dictionary meta file: %w", err)
	}

	// parse the meta file
	metadata, err := NewMetadataFromFile(fs, tempFile.Name())
	if err != nil {
		return &Metadata{}, err
	}
	return &metadata, nil
}

// Validate checks the current database to ensure file integrity and if it can be used by this version of the application.
func (c *Curator) Validate() (uint64, error) {
	return c.validate(c.config.CacheDir)
}

func (c *Curator) ImportFrom(cpeDictionaryPath string) error {
	tempDir, err := ioutil.TempDir("", "cpe-dictionary-import")
	if err != nil {
		return fmt.Errorf("unable to create CPE dictionary temp dir: %w", err)
	}

	err = file.UnGzip(tempDir, cpeDictionaryPath)
	if err != nil {
		return err
	}

	checksum, err := file.HashFile(c.fs, cpeDictionaryPath, sha256.New())
	if err != nil {
		return fmt.Errorf("unable to calculate archive checksum: %w", err)
	}

	metadata := &Metadata{Date: time.Now(), Checksum: checksum}
	err = c.index(metadata, tempDir)
	if err != nil {
		return err
	}

	_, err = c.validate(tempDir)
	if err != nil {
		return err
	}

	err = c.activate(tempDir)
	if err != nil {
		return err
	}

	return c.fs.RemoveAll(tempDir)
}

func (c *Curator) UpdateTo(metadata *Metadata, downloadProgress, importProgress *progress.Manual, stage *progress.Stage) error {
	stage.Current = "downloading"
	tempDir, err := c.download(metadata, downloadProgress)
	if err != nil {
		return err
	}

	stage.Current = "indexing"
	err = c.index(metadata, tempDir)
	if err != nil {
		return err
	}

	stage.Current = "validating"
	_, err = c.validate(tempDir)
	if err != nil {
		return err
	}

	stage.Current = "importing"
	err = c.activate(tempDir)
	if err != nil {
		return err
	}
	stage.Current = "updated"
	importProgress.N = importProgress.Total
	importProgress.SetCompleted()

	return c.fs.RemoveAll(tempDir)
}

func (c *Curator) download(metadata *Metadata, downloadProgress *progress.Manual) (string, error) {
	tempDir, err := ioutil.TempDir("", "cpe-dictionary")
	if err != nil {
		return "", fmt.Errorf("unable to create CPE dictionary temp dir: %w", err)
	}

	// download the cpe dictionary to the temp file
	tempFile := path.Join(tempDir, FileName)
	updateURL, err := url.Parse(c.config.UpdateURL)
	if err != nil {
		return "", fmt.Errorf("invalid CPE dictionary update url (%s): %w", c.config.UpdateURL, err)
	}

	// from go-getter, adding a checksum as a query string will validate the payload after download
	// note: the checksum query parameter is not sent to the server
	query := updateURL.Query()
	query.Add("checksum", metadata.Checksum)
	updateURL.RawQuery = query.Encode()

	// go-getter will download the file to the destination
	err = c.downloader.GetFile(tempFile, c.config.UpdateURL, downloadProgress)
	if err != nil {
		return "", fmt.Errorf("unable to download CPE dictionary: %w", err)
	}

	return tempDir, nil
}

func (c *Curator) index(metadata *Metadata, tempDir string) error {
	// create the CPE dictionary index
	indexPath := path.Join(tempDir, metadata.toIndexName())
	index, err := c.createDictionaryIndex(indexPath)
	if err != nil {
		return fmt.Errorf("unable to create new CPE dictionary index: %w", err)
	}
	defer func() {
		err = index.Close()
		if err != nil {
			log.Errorf("unable to close index (%s): %w", index, err)
		}
	}()

	cpeArchivePath := path.Join(tempDir, FileName)
	cpeArchiveFile, err := c.fs.Open(cpeArchivePath)
	if err != nil {
		return fmt.Errorf("unable to open CPE dictionary archive: %w", err)
	}

	cpeList, err := cpedict.Decode(cpeArchiveFile)
	if err != nil {
		return fmt.Errorf("unable to parse CPE dictionary: %w", err)
	}

	batchIndex := newBatchIndex(index, cpeList)
	err = index.Batch(batchIndex)
	if err != nil {
		return fmt.Errorf("unable to index CPE entries: %w", err)
	}

	metadata.Count, err = index.DocCount()
	if err != nil {
		return fmt.Errorf("unable to query CPE dictionary index: %w", err)
	}

	// Write metadata file
	metadataPath := path.Join(tempDir, MetadataFileName)
	err = metadata.Write(metadataPath)
	if err != nil {
		return fmt.Errorf("unable to write CPE dictionary metadata: %w", err)
	}

	// Remove xml file
	err = c.fs.Remove(cpeArchivePath)
	if err != nil {
		log.Warnf("failed to remove cpe archive file %w", err)
	}

	return nil
}

func newBatchIndex(index bleve.Index, list *cpedict.CPEList) *bleve.Batch {
	var batchIndex = index.NewBatch()
	for _, item := range list.Items {
		if item.Deprecated {
			continue
		}

		if item.CPE23.Name.Part != "a" {
			continue
		}

		entry := CPE{
			Vendor:  wfn.StripSlashes(item.CPE23.Name.Vendor),
			Product: wfn.StripSlashes(item.CPE23.Name.Product),
		}

		id := entryToID(entry)
		err := batchIndex.Index(id, entry)
		if err != nil {
			fmt.Println("failed to index CPE entry", err)
		}
	}
	return batchIndex
}

func entryToID(entry CPE) string {
	parts := make([]string, 2)
	parts[0] = entry.Vendor
	parts[1] = entry.Product
	return strings.Join(parts, ":")
}

func (c *Curator) createDictionaryIndex(indexPath string) (bleve.Index, error) {
	var err error

	mapping := bleve.NewIndexMapping()
	err = RegisterNvdAnalyzer(mapping)
	if err != nil {
		return nil, fmt.Errorf("unable to register nvd analyzer: %w", err)
	}

	textFieldMapping := bleve.NewTextFieldMapping()
	textFieldMapping.Analyzer = NvdAnalyzerName
	textFieldMapping.Store = false
	textFieldMapping.IncludeTermVectors = false
	textFieldMapping.IncludeInAll = false
	textFieldMapping.DocValues = false

	docMapping := bleve.NewDocumentMapping()
	docMapping.AddFieldMappingsAt("vendor", textFieldMapping)
	docMapping.AddFieldMappingsAt("product", textFieldMapping)
	mapping.AddDocumentMapping("cpe", docMapping)

	index, err := bleve.New(indexPath, mapping)
	if err != nil {
		return nil, fmt.Errorf("unable to create bleve index: %w", err)
	}
	return index, nil
}

func (c *Curator) validate(cpeDictionaryPath string) (uint64, error) {
	// check that the disk checksum still matches the db payload
	metadata, err := NewMetadataFromDir(c.fs, cpeDictionaryPath)
	if err != nil {
		return 0, fmt.Errorf("failed to parse database metadata (%s): %w", cpeDictionaryPath, err)
	}
	if metadata == nil {
		return 0, fmt.Errorf("database metadata not found: %s", cpeDictionaryPath)
	}

	if c.config.ValidateChecksum {
		valid, actualHash, err := file.ValidateByHash(c.fs, cpeDictionaryPath, metadata.Checksum)
		if err != nil {
			return 0, err
		}
		if !valid {
			return 0, fmt.Errorf("bad CPE dictionary checksum (%s): %q vs %q", cpeDictionaryPath, metadata.Checksum, actualHash)
		}
	}

	indexPath := path.Join(cpeDictionaryPath, metadata.toIndexName())
	index, err := bleve.Open(indexPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open CPE dictionary index (%s): %w", cpeDictionaryPath, err)
	}
	defer func() {
		err = index.Close()
		if err != nil {
			log.Errorf("unable to close CPE dictionary idnex (%s): %w", indexPath, err)
		}
	}()

	count, err := index.DocCount()
	if err != nil {
		return 0, fmt.Errorf("failed to query CPE dictionary index (%s): %w", cpeDictionaryPath, err)
	}
	if count != metadata.Count {
		return 0, fmt.Errorf("bad CPE dictionary document count (%s): %d vs %d", cpeDictionaryPath, metadata.Count, count)
	}

	return count, nil
}

// activate move the indexed CPE dictionary to the cache directory
func (c *Curator) activate(cpeDictionaryPath string) error {
	_, err := c.fs.Stat(c.config.CacheDir)
	if !os.IsNotExist(err) {
		// remove any previous dictionary
		err = c.Delete()
		if err != nil {
			return fmt.Errorf("failed to purge existing CPE dictionary: %w", err)
		}
	}

	// create the application cache directory
	err = c.fs.MkdirAll(c.config.CacheDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create db directory: %w", err)
	}

	// activate the new CPE dictionary index
	return file.MoveDir(c.fs, cpeDictionaryPath, c.config.CacheDir)
}
