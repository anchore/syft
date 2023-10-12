package static_binary

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
)

func scanFile(reader unionreader.UnionReader, filename string) ([]byte, []string, error) {
	bi, err := io.ReadAll(reader)
	if err != nil {
		log.WithFields("file", filename, "error", err).Trace("unable to read binary")
		return bi, nil, err
	}
	//br is our byte reader
	br := bytes.NewReader(bi)
	//make a new elf file we can play with
	e, err := elf.NewFile(br)
	if e != nil {
		//We were able to read the file. Now let's do stuff with it.

		//symbols should be the .so filenames
		symbols, err := e.ImportedLibraries()
		if err != nil {
			log.Debugf("unable to read elf binary: %s", err)
			symbols = nil
		}
		//notes will be the raw data pulled from the section
		noteSection := e.Section(".note.package")
		if noteSection != nil {
			notes, err := noteSection.Data()
			if notes == nil {
				log.Debugf("unable to read .note.package")
			}
			return notes, symbols, err
		} else {
			//TODO:

			//THere was no note section. We need to infer info here.

			//We should look at maybe a file contents or file template matcher here
			//then we create package using that

			//look at the classifer stuff in binary catloger and we need to implement that here.

			fmt.Printf("ver: %v\n", e.Version)

		}

	}
	return nil, nil, err

}
