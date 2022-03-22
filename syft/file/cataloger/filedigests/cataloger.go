package filedigests

import (
	"crypto"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

var errUndigestableFile = errors.New("undigestable file")

type Cataloger struct {
	hashes []crypto.Hash
}

func NewCataloger(hashes []crypto.Hash) (*Cataloger, error) {
	return &Cataloger{
		hashes: hashes,
	}, nil
}

func (i *Cataloger) Catalog(resolver source.FileResolver) (map[file.Coordinates][]file.Digest, error) {
	results := make(map[file.Coordinates][]file.Digest)
	locations := source.AllRegularFiles(resolver)
	stage, prog := digestsCatalogingProgress(int64(len(locations)))
	for _, location := range locations {
		stage.Current = location.RealPath
		result, err := i.catalogLocation(resolver, location)

		if errors.Is(err, errUndigestableFile) {
			continue
		}

		if internal.IsErrPathPermission(err) {
			log.Debugf("file digests cataloger skipping %q: %+v", location.RealPath, err)
			continue
		}

		if err != nil {
			return nil, err
		}
		prog.N++
		results[location.Coordinates] = result
	}
	log.Debugf("file digests cataloger processed %d files", prog.N)
	prog.SetCompleted()
	return results, nil
}

func (i *Cataloger) catalogLocation(resolver source.FileResolver, location file.Location) ([]file.Digest, error) {
	meta, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return nil, err
	}

	// we should only attempt to report digests for files that are regular files (don't attempt to resolve links)
	if meta.Type != file.RegularFile {
		return nil, errUndigestableFile
	}

	contentReader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, location.AccessPath)

	// create a set of hasher objects tied together with a single writer to feed content into
	hashers := make([]hash.Hash, len(i.hashes))
	writers := make([]io.Writer, len(i.hashes))
	for idx, hashObj := range i.hashes {
		hashers[idx] = hashObj.New()
		writers[idx] = hashers[idx]
	}

	size, err := io.Copy(io.MultiWriter(writers...), contentReader)
	if err != nil {
		return nil, internal.ErrPath{Context: "digests-cataloger", Path: location.RealPath, Err: err}
	}

	if size == 0 {
		return make([]file.Digest, 0), nil
	}

	result := make([]file.Digest, len(i.hashes))
	// only capture digests when there is content. It is important to do this based on SIZE and not
	// FILE TYPE. The reasoning is that it is possible for a tar to be crafted with a header-only
	// file type but a body is still allowed.
	for idx, hasher := range hashers {
		result[idx] = file.Digest{
			Algorithm: file.DigestAlgorithmName(i.hashes[idx]),
			Value:     fmt.Sprintf("%+x", hasher.Sum(nil)),
		}
	}

	return result, nil
}

func digestsCatalogingProgress(locations int64) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{
		Total: locations,
	}

	bus.Publish(partybus.Event{
		Type: event.FileDigestsCatalogerStarted,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}
