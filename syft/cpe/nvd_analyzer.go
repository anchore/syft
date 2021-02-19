package cpe

import (
	"github.com/blevesearch/bleve/v2/analysis/analyzer/custom"
	"github.com/blevesearch/bleve/v2/analysis/token/lowercase"
	"github.com/blevesearch/bleve/v2/analysis/token/stop"
	"github.com/blevesearch/bleve/v2/analysis/tokenizer/regexp"
	"github.com/blevesearch/bleve/v2/analysis/tokenmap"
	"github.com/blevesearch/bleve/v2/mapping"
)

const NvdAnalyzerName = "nvd"
const TokenFilterName = "generic_exclude"
const TokenizerName = "alpha_numeric"

// TODO configurable ignore list?
var genericTokenMap = map[string]interface{}{
	"type":   tokenmap.Name,
	"tokens": []interface{}{"project"},
}

var excludeGenericTokenFilter = map[string]interface{}{
	"type":           stop.Name,
	"stop_token_map": TokenFilterName,
}

var alphaNumericTokenizer = map[string]interface{}{
	"type":   regexp.Name,
	"regexp": "[a-zA-Z0-9]+",
}

var NvdAnalyzerConfig = map[string]interface{}{
	"type":         custom.Name,
	"char_filters": []string{},
	"tokenizer":    TokenizerName,
	"token_filters": []string{
		lowercase.Name,
		TokenFilterName,
	},
}

func RegisterNvdAnalyzer(m *mapping.IndexMappingImpl) error {
	var err error

	err = m.AddCustomTokenMap(TokenFilterName, genericTokenMap)
	if err != nil {
		return err
	}

	err = m.AddCustomTokenFilter(TokenFilterName, excludeGenericTokenFilter)
	if err != nil {
		return err
	}

	err = m.AddCustomTokenizer(TokenizerName, alphaNumericTokenizer)
	if err != nil {
		return err
	}

	return m.AddCustomAnalyzer(NvdAnalyzerName, NvdAnalyzerConfig)
}
