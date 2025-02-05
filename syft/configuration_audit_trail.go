package syft

import (
	"encoding/json"
	"reflect"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
)

// configurationAuditTrail is all input configuration was used to generate the SBOM
type configurationAuditTrail struct {
	Search         cataloging.SearchConfig         `json:"search" yaml:"search" mapstructure:"search"`
	Relationships  cataloging.RelationshipsConfig  `json:"relationships" yaml:"relationships" mapstructure:"relationships"`
	DataGeneration cataloging.DataGenerationConfig `json:"data-generation" yaml:"data-generation" mapstructure:"data-generation"`
	Packages       pkgcataloging.Config            `json:"packages" yaml:"packages" mapstructure:"packages"`
	Files          filecataloging.Config           `json:"files" yaml:"files" mapstructure:"files"`
	Licenses       cataloging.LicenseConfig        `json:"licenses" yaml:"licenses" mapstructure:"licenses"`
	Catalogers     catalogerManifest               `json:"catalogers" yaml:"catalogers" mapstructure:"catalogers"`
	ExtraConfigs   any                             `json:"extra,omitempty" yaml:"extra" mapstructure:"extra"`
}

type catalogerManifest struct {
	Requested cataloging.SelectionRequest `json:"requested" yaml:"requested" mapstructure:"requested"`
	Used      []string                    `json:"used" yaml:"used" mapstructure:"used"`
}

type marshalAPIConfiguration configurationAuditTrail

func (cfg configurationAuditTrail) MarshalJSON() ([]byte, error) {
	// since the api configuration is placed into the SBOM in an empty interface, and we want a stable ordering of
	// keys (not guided by the struct ordering) we need to convert the struct to a map. This is best done with
	// simply marshalling and unmarshalling. Mapstructure is used to ensure we are honoring all json struct
	// tags. Once we have a map, we can lean on the stable ordering of json map keys in the stdlib. This is an
	// implementation detail that can be at least relied on until Go 2 (at which point it can change).
	// This dance allows us to guarantee ordering of keys in the configuration section of the SBOM.

	initialJSON, err := json.Marshal(marshalAPIConfiguration(cfg))
	if err != nil {
		return nil, err
	}

	var dataMap map[string]interface{}
	if err := json.Unmarshal(initialJSON, &dataMap); err != nil {
		return nil, err
	}

	if v, exists := dataMap["extra"]; exists && v == nil {
		// remove the extra key if it renders as nil
		delete(dataMap, "extra")
	}

	return marshalSorted(dataMap)
}

// marshalSorted recursively marshals a map with sorted keys
func marshalSorted(m interface{}) ([]byte, error) {
	if reflect.TypeOf(m).Kind() != reflect.Map {
		return json.Marshal(m)
	}

	val := reflect.ValueOf(m)
	sortedMap := make(map[string]interface{})

	for _, key := range val.MapKeys() {
		value := val.MapIndex(key).Interface()

		if value != nil && reflect.TypeOf(value).Kind() == reflect.Map {
			sortedValue, err := marshalSorted(value)
			if err != nil {
				return nil, err
			}
			sortedMap[key.String()] = json.RawMessage(sortedValue)
		} else {
			sortedMap[key.String()] = value
		}
	}

	return json.Marshal(sortedMap)
}
