package dirs

import (
	"encoding/json"
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal/log"
)

type Presenter struct {
	catalog *pkg.Catalog
}

func NewPresenter(catalog *pkg.Catalog) *Presenter {
	return &Presenter{
		catalog: catalog,
	}
}

type document struct {
	Artifacts []artifact `json:"artifacts"`
}

type dir struct {
	Path string `json:"path"`
}

type source struct {
	FoundBy string   `json:"foundBy"`
	Layer   int      `json:"layer"`
	Effects []string `json:"effects"`
}

type artifact struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Type      string      `json:"type"`
	Cataloger string      `json:"cataloger"`
	Sources   []source    `json:"sources"`
	Metadata  interface{} `json:"metadata"`
}

func (pres *Presenter) Present(output io.Writer) error {
	doc := document{
		Artifacts: make([]artifact, 0),
	}

	// populate artifacts...
	for p := range pres.catalog.Enumerate() {
		art := artifact{
			Name:     p.Name,
			Version:  p.Version,
			Type:     p.Type.String(),
			Sources:  make([]source, len(p.Source)),
			Metadata: p.Metadata,
		}

		// FIXME: there is no image in a dir-based scan
		for idx := range p.Source {
			// fileMetadata, err := pres.img.FileCatalog.Get(src)
			// if err != nil {
			// 	// TODO: test case
			// 	log.Errorf("could not get metadata from catalog (presenter=json): %+v", src)
			// }

			srcObj := source{
				FoundBy: "FoundBy",
				Layer:   0,
				Effects: []string{}, // TODO
			}
			art.Sources[idx] = srcObj
		}

		doc.Artifacts = append(doc.Artifacts, art)
	}

	bytes, err := json.Marshal(&doc)
	if err != nil {
		log.Errorf("failed to marshal json (presenter=json): %w", err)
	}

	_, err = output.Write(bytes)
	return err
}
