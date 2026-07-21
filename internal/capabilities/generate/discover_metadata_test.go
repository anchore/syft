package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyParserObservations(t *testing.T) {
	tests := []struct {
		name             string
		cataloger        DiscoveredCataloger
		index            *TestObservationIndex
		wantFoundData    bool
		wantMetadataType string
		wantPackageType  string
	}{
		{
			name: "parser observations applied to matching parser",
			cataloger: DiscoveredCataloger{
				Name:        "test-cataloger",
				PackageName: "testpkg",
				Parsers: []DiscoveredParser{
					{ParserFunction: "parseTestFile"},
				},
			},
			index: func() *TestObservationIndex {
				idx := newTestObservationIndex()
				idx.setParserObservations("testpkg", "parseTestFile", &TypeObservation{
					MetadataTypes: []string{"pkg.TestMetadata"},
					PackageTypes:  []string{"test-type"},
				})
				return idx
			}(),
			wantFoundData:    true,
			wantMetadataType: "pkg.TestMetadata",
			wantPackageType:  "test-type",
		},
		{
			name: "no observations found for parser",
			cataloger: DiscoveredCataloger{
				Name:        "test-cataloger",
				PackageName: "testpkg",
				Parsers: []DiscoveredParser{
					{ParserFunction: "parseOtherFile"},
				},
			},
			index: func() *TestObservationIndex {
				idx := newTestObservationIndex()
				idx.setParserObservations("testpkg", "parseTestFile", &TypeObservation{
					MetadataTypes: []string{"pkg.TestMetadata"},
				})
				return idx
			}(),
			wantFoundData: false,
		},
		{
			name: "multiple parsers with mixed observations",
			cataloger: DiscoveredCataloger{
				Name:        "test-cataloger",
				PackageName: "testpkg",
				Parsers: []DiscoveredParser{
					{ParserFunction: "parseFirst"},
					{ParserFunction: "parseSecond"},
				},
			},
			index: func() *TestObservationIndex {
				idx := newTestObservationIndex()
				idx.setParserObservations("testpkg", "parseFirst", &TypeObservation{
					MetadataTypes: []string{"pkg.FirstMetadata"},
				})
				// parseSecond has no observations
				return idx
			}(),
			wantFoundData:    true,
			wantMetadataType: "pkg.FirstMetadata",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFoundData := applyParserObservations(&tt.cataloger, tt.index)
			require.Equal(t, tt.wantFoundData, gotFoundData)

			if tt.wantFoundData && tt.wantMetadataType != "" {
				require.Contains(t, tt.cataloger.Parsers[0].MetadataTypes, tt.wantMetadataType)
			}

			if tt.wantFoundData && tt.wantPackageType != "" {
				require.Contains(t, tt.cataloger.Parsers[0].PackageTypes, tt.wantPackageType)
			}
		})
	}
}

func TestApplySingleParserCatalogerObservations(t *testing.T) {
	tests := []struct {
		name             string
		cataloger        DiscoveredCataloger
		catalogerObs     *TypeObservation
		wantFoundData    bool
		wantMetadataType []string
		wantPackageType  []string
	}{
		{
			name: "cataloger-level observations applied to single parser",
			cataloger: DiscoveredCataloger{
				Name: "single-parser-cataloger",
				Parsers: []DiscoveredParser{
					{ParserFunction: "parseSingle"},
				},
			},
			catalogerObs: &TypeObservation{
				MetadataTypes: []string{"pkg.CatalogerMetadata"},
				PackageTypes:  []string{"cataloger-type"},
			},
			wantFoundData:    true,
			wantMetadataType: []string{"pkg.CatalogerMetadata"},
			wantPackageType:  []string{"cataloger-type"},
		},
		{
			name: "cataloger-level merges with existing parser-level observations",
			cataloger: DiscoveredCataloger{
				Name: "single-parser-cataloger",
				Parsers: []DiscoveredParser{
					{
						ParserFunction: "parseSingle",
						MetadataTypes:  []string{"pkg.ParserMetadata"},
						PackageTypes:   []string{"parser-type"},
					},
				},
			},
			catalogerObs: &TypeObservation{
				MetadataTypes: []string{"pkg.CatalogerMetadata"},
				PackageTypes:  []string{"cataloger-type"},
			},
			wantFoundData:    true,
			wantMetadataType: []string{"pkg.CatalogerMetadata", "pkg.ParserMetadata"},
			wantPackageType:  []string{"cataloger-type", "parser-type"},
		},
		{
			name: "empty cataloger observations",
			cataloger: DiscoveredCataloger{
				Name: "single-parser-cataloger",
				Parsers: []DiscoveredParser{
					{ParserFunction: "parseSingle"},
				},
			},
			catalogerObs:  &TypeObservation{},
			wantFoundData: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFoundData := applySingleParserCatalogerObservations(&tt.cataloger, tt.catalogerObs)
			require.Equal(t, tt.wantFoundData, gotFoundData)

			if tt.wantFoundData {
				if len(tt.wantMetadataType) > 0 {
					require.ElementsMatch(t, tt.wantMetadataType, tt.cataloger.Parsers[0].MetadataTypes)
				}
				if len(tt.wantPackageType) > 0 {
					require.ElementsMatch(t, tt.wantPackageType, tt.cataloger.Parsers[0].PackageTypes)
				}
			}
		})
	}
}

func TestApplyMultiParserCatalogerObservations(t *testing.T) {
	tests := []struct {
		name          string
		cataloger     DiscoveredCataloger
		catalogerObs  *TypeObservation
		wantFoundData bool
		// expectations for each parser by index
		wantParser0HasMetadata bool
		wantParser1HasMetadata bool
	}{
		{
			name: "all parsers without data - cataloger-level applied to all",
			cataloger: DiscoveredCataloger{
				Name: "multi-parser-cataloger",
				Parsers: []DiscoveredParser{
					{ParserFunction: "parseFirst"},
					{ParserFunction: "parseSecond"},
				},
			},
			catalogerObs: &TypeObservation{
				MetadataTypes: []string{"pkg.SharedMetadata"},
				PackageTypes:  []string{"shared-type"},
			},
			wantFoundData:          true,
			wantParser0HasMetadata: true,
			wantParser1HasMetadata: true,
		},
		{
			name: "some parsers have data - cataloger-level only fills gaps",
			cataloger: DiscoveredCataloger{
				Name: "multi-parser-cataloger",
				Parsers: []DiscoveredParser{
					{
						ParserFunction: "parseFirst",
						MetadataTypes:  []string{"pkg.FirstMetadata"},
					},
					{ParserFunction: "parseSecond"}, // no data
				},
			},
			catalogerObs: &TypeObservation{
				MetadataTypes: []string{"pkg.SharedMetadata"},
			},
			wantFoundData:          true,
			wantParser0HasMetadata: false, // already has data, not overwritten
			wantParser1HasMetadata: true,  // gets cataloger-level data
		},
		{
			name: "all parsers have data - cataloger-level not applied",
			cataloger: DiscoveredCataloger{
				Name: "multi-parser-cataloger",
				Parsers: []DiscoveredParser{
					{
						ParserFunction: "parseFirst",
						MetadataTypes:  []string{"pkg.FirstMetadata"},
					},
					{
						ParserFunction: "parseSecond",
						MetadataTypes:  []string{"pkg.SecondMetadata"},
					},
				},
			},
			catalogerObs: &TypeObservation{
				MetadataTypes: []string{"pkg.SharedMetadata"},
			},
			wantFoundData:          false,
			wantParser0HasMetadata: false, // should not have shared metadata
			wantParser1HasMetadata: false, // should not have shared metadata
		},
		{
			name: "empty cataloger observations",
			cataloger: DiscoveredCataloger{
				Name: "multi-parser-cataloger",
				Parsers: []DiscoveredParser{
					{ParserFunction: "parseFirst"},
					{ParserFunction: "parseSecond"},
				},
			},
			catalogerObs:           &TypeObservation{},
			wantFoundData:          false,
			wantParser0HasMetadata: false,
			wantParser1HasMetadata: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFoundData := applyMultiParserCatalogerObservations(&tt.cataloger, tt.catalogerObs)
			require.Equal(t, tt.wantFoundData, gotFoundData)

			if tt.wantParser0HasMetadata {
				require.Contains(t, tt.cataloger.Parsers[0].MetadataTypes, "pkg.SharedMetadata",
					"parser 0 should have shared metadata")
			} else if len(tt.catalogerObs.MetadataTypes) > 0 {
				// if cataloger has metadata but we don't expect it in parser 0, verify it's not there
				require.NotContains(t, tt.cataloger.Parsers[0].MetadataTypes, "pkg.SharedMetadata",
					"parser 0 should not have shared metadata")
			}

			if tt.wantParser1HasMetadata {
				require.Contains(t, tt.cataloger.Parsers[1].MetadataTypes, "pkg.SharedMetadata",
					"parser 1 should have shared metadata")
			} else if len(tt.catalogerObs.MetadataTypes) > 0 {
				// if cataloger has metadata but we don't expect it in parser 1, verify it's not there
				require.NotContains(t, tt.cataloger.Parsers[1].MetadataTypes, "pkg.SharedMetadata",
					"parser 1 should not have shared metadata")
			}
		})
	}
}

func TestMergeAndDeduplicateStrings(t *testing.T) {
	tests := []struct {
		name       string
		existing   []string
		additional []string
		want       []string
	}{
		{
			name:       "merge with duplicates",
			existing:   []string{"a", "b"},
			additional: []string{"b", "c"},
			want:       []string{"a", "b", "c"},
		},
		{
			name:       "empty existing",
			existing:   []string{},
			additional: []string{"a", "b"},
			want:       []string{"a", "b"},
		},
		{
			name:       "empty additional",
			existing:   []string{"a", "b"},
			additional: []string{},
			want:       []string{"a", "b"},
		},
		{
			name:       "both empty",
			existing:   []string{},
			additional: []string{},
			want:       []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeAndDeduplicateStrings(tt.existing, tt.additional)
			require.ElementsMatch(t, tt.want, got)
		})
	}
}
