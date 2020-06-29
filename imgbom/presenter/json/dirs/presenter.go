package dirs

import (
	"encoding/json"
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal/log"
)

type Presenter struct {
	catalog *pkg.Catalog
	path    string
}

func NewPresenter(catalog *pkg.Catalog, path string) *Presenter {
	return &Presenter{
		catalog: catalog,
		path:    path,
	}
}

type document struct {
	Artifacts []artifact `json:"artifacts"`
	Source    string
}

type source struct {
	FoundBy string   `json:"foundBy"`
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
		Source:    pres.path,
	}

	// populate artifacts...
	// TODO: move this into a common package so that other text presenters can reuse
	for p := range pres.catalog.Enumerate() {
		art := artifact{
			Name:     p.Name,
			Version:  p.Version,
			Type:     p.Type.String(),
			Sources:  make([]source, len(p.Source)),
			Metadata: p.Metadata,
		}

		for idx := range p.Source {
			srcObj := source{
				FoundBy: p.FoundBy,
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
