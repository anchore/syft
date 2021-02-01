package cpe

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/pkg"

	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/blevesearch/bleve/v2"
)

var endingCharacterRegexp = regexp.MustCompile("[A-Za-z]+$")
var NotFound = SearchResult{}

type BleveDictionary struct {
	Index            bleve.Index
	MinimumScore     float64
	SpecificVendors  []SpecificCandidate
	SpecificProducts []SpecificCandidate
}

type WeightedSuffix struct {
	Suffix string
	Boost  float64
}

type SearchResult struct {
	Product string
	Vendor  string
}

// identifyPackageCPEs Lookup the CPE, from candidate vendor and products
func (d BleveDictionary) IdentifyPackageCPEs(p pkg.Package) []pkg.CPE {
	vendors := d.candidateVendors(p)
	products := d.candidateProducts(p)
	targetSws := candidateTargetSoftwareAttrs(p)
	version, update := extractVersionAndUpdate(p)

	CPEs := make([]pkg.CPE, 0)
	result, err := d.search(vendors, products)
	if err != nil {
		log.Warnf("unable to retrieve CPE from dictionary: %w", err)
		return CPEs
	}
	if result == NotFound {
		log.Debug("no CPE found for package %w", p.Name)
		return CPEs
	}

	for _, targetSw := range targetSws {
		CPEs = append(CPEs, newCPE(result.Product, result.Vendor, version, update, targetSw))
	}

	sort.Sort(ByCPESpecificity(CPEs))
	return CPEs
}

func (d BleveDictionary) search(vendors []Candidate, products []Candidate) (SearchResult, error) {
	globalQuery := bleve.NewBooleanQuery()

	// Vendor
	vendorQuery := bleve.NewBooleanQuery()
	for _, vendor := range vendors {
		var q = bleve.NewMatchQuery(vendor.Term)
		q.SetField("vendor")
		q.SetBoost(vendor.Boost)
		vendorQuery.AddShould(q)
	}
	globalQuery.AddMust(vendorQuery)

	// Product
	productQuery := bleve.NewBooleanQuery()
	for _, product := range products {
		var q = bleve.NewMatchQuery(product.Term)
		q.SetField("product")
		q.SetBoost(product.Boost)
		productQuery.AddShould(q)
	}
	globalQuery.AddMust(productQuery)

	searchRequest := bleve.NewSearchRequest(globalQuery)
	searchResults, err := d.Index.Search(searchRequest)
	if err != nil {
		return NotFound, fmt.Errorf("failed to search CPE dictionary: %w", err)
	}

	if len(searchResults.Hits) > 0 {
		for _, result := range searchResults.Hits {
			if result.Score < d.MinimumScore {
				continue
			}

			fields := strings.Split(result.ID, ":")
			vendor := fields[0]
			product := fields[1]

			if d.validateResult(vendors, vendor) && d.validateResult(products, product) {
				return SearchResult{Vendor: vendor, Product: product}, nil
			}
		}
	}

	return NotFound, nil
}

func (d BleveDictionary) Close() error {
	return d.Index.Close()
}

func (d BleveDictionary) candidateVendors(p pkg.Package) []Candidate {
	vendors := []Candidate{{Term: p.Name, Boost: 0.5}}
	switch p.Language {
	case pkg.Python:
		vendors = append(vendors, Candidate{Term: fmt.Sprintf("python-%s", p.Name), Boost: 1})
	case pkg.Java:
		if p.MetadataType == pkg.JavaMetadataType {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
				vendors = vendorsFromJavaMetadata(metadata, vendors)
			}
		}
	}

	for _, specificVendor := range d.SpecificVendors {
		if specificVendor.Match.MatchString(p.Name) {
			vendors = append(vendors, specificVendor.Candidate)
		}
	}

	return vendors
}

func vendorsFromJavaMetadata(metadata pkg.JavaMetadata, vendors []Candidate) []Candidate {
	if metadata.Manifest != nil {
		for _, section := range getManifestSections() {
			for _, weightedSuffix := range getVendorManifestSectionSuffixes() {
				if term, ok := metadata.Manifest.Main[section+weightedSuffix.Suffix]; ok {
					vendors = append(vendors, Candidate{Term: term, Boost: weightedSuffix.Boost})
				}
			}
		}
	}

	if metadata.PomProperties != nil {
		vendors = append(vendors, Candidate{Term: RemoveTldPrefix(metadata.PomProperties.GroupID), Boost: 2})
	}
	return vendors
}

func (d BleveDictionary) candidateProducts(p pkg.Package) []Candidate {
	products := []Candidate{{Term: p.Name, Boost: 2}}
	if p.Language == pkg.Java {
		if p.MetadataType == pkg.JavaMetadataType {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
				products = productsFromJavaMetadata(metadata, products)
			}
		}
	}

	for _, specificProduct := range d.SpecificProducts {
		if specificProduct.Match.MatchString(p.Name) {
			products = append(products, specificProduct.Candidate)
		}
	}

	return products
}

func productsFromJavaMetadata(metadata pkg.JavaMetadata, products []Candidate) []Candidate {
	if metadata.Manifest != nil {
		for _, section := range getManifestSections() {
			for _, weightedSuffix := range getProductManifestSectionSuffixes() {
				if term, ok := metadata.Manifest.Main[section+weightedSuffix.Suffix]; ok {
					products = append(products, Candidate{Term: term, Boost: weightedSuffix.Boost})
				}
			}
		}
		if term, ok := metadata.Manifest.Main["Long-Name"]; ok {
			products = append(products, Candidate{Term: term, Boost: 1})
		}
	}

	if metadata.PomProperties != nil {
		products = append(products, Candidate{Term: metadata.PomProperties.ArtifactID, Boost: 1})
	}
	return products
}

func (d BleveDictionary) validateResult(candidates []Candidate, match string) bool {
	nvdAnalyzer := d.Index.Mapping().AnalyzerNamed(NvdAnalyzerName)
	parts := nvdAnalyzer.Analyze([]byte(match))
	for _, token := range parts {
		tokenFound := false
		for _, candidate := range candidates {
			if strings.Contains(strings.ToLower(candidate.Term), string(token.Term)) {
				tokenFound = true
			}
		}
		if !tokenFound {
			return false
		}
	}
	return true
}

func getVendorManifestSectionSuffixes() []WeightedSuffix {
	return []WeightedSuffix{
		{"-Vendor-Id", 2},
		{"-Vendor", 2},
		{"-Url", 0.5},
	}
}

func getProductManifestSectionSuffixes() []WeightedSuffix {
	return []WeightedSuffix{
		{"-Title", 2},
		{"-Name", 2},
		{"-SymbolicName", 1},
		{"-Url", 0.5},
	}
}

func getManifestSections() []string {
	return []string{"Implementation", "Specification", "Application", "Bundle"}
}

func NewBleveDictionary(index bleve.Index, config config.CPEDictionary) Dictionary {
	return &BleveDictionary{
		Index:            index,
		MinimumScore:     config.MinimumScore,
		SpecificVendors:  SpecificCandidateFromConfig(config.SpecificVendors),
		SpecificProducts: SpecificCandidateFromConfig(config.SpecificProducts),
	}
}

func SpecificCandidateFromConfig(specificMatches []config.SpecificMatch) []SpecificCandidate {
	candidates := make([]SpecificCandidate, len(specificMatches))
	for i, specificMatch := range specificMatches {
		match, err := regexp.Compile(specificMatch.Match)
		if err != nil {
			log.Warnf("failed to compile regexp (%w): %w", specificMatch.Match, err)
			continue
		}

		candidates[i] = SpecificCandidate{
			Match: *match,
			Candidate: Candidate{
				Term:  specificMatch.Term,
				Boost: specificMatch.Boost,
			},
		}
	}
	return candidates
}
