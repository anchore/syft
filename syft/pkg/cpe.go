package pkg

import (
	"fmt"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

type CPE = wfn.Attributes

func NewCPE(cpeStr string) (CPE, error) {
	value, err := wfn.Parse(cpeStr)
	if err != nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q: %w", cpeStr, err)
	}

	if value == nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q", cpeStr)
	}

	// we need to compare the raw data since we are constructing CPEs in other locations
	value.Vendor = normalizeCpeField(value.Vendor)
	value.Product = normalizeCpeField(value.Product)
	value.Language = normalizeCpeField(value.Language)
	value.Version = normalizeCpeField(value.Version)
	value.TargetSW = normalizeCpeField(value.TargetSW)
	value.Part = normalizeCpeField(value.Part)
	value.Edition = normalizeCpeField(value.Edition)
	value.Other = normalizeCpeField(value.Other)
	value.SWEdition = normalizeCpeField(value.SWEdition)
	value.TargetHW = normalizeCpeField(value.TargetHW)
	value.Update = normalizeCpeField(value.Update)

	return *value, nil
}

func MustCPE(cpeStr string) CPE {
	c, err := NewCPE(cpeStr)
	if err != nil {
		panic(err)
	}
	return c
}

func normalizeCpeField(field string) string {
	// keep dashes and forward slashes unescaped
	if field == "*" {
		return wfn.Any
	}
	return strings.ReplaceAll(wfn.StripSlashes(field), `\/`, "/")
}
