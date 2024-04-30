package main

type CpeItem struct {
	Name       string `xml:"name,attr"`
	Title      string `xml:"title"`
	References struct {
		Reference []struct {
			Href string `xml:"href,attr"`
			Body string `xml:",chardata"`
		} `xml:"reference"`
	} `xml:"references"`
	Cpe23Item struct {
		Name        string `xml:"name,attr"`
		Deprecation struct {
			DeprecatedBy struct {
				Name string `xml:"name,attr"`
			} `xml:"deprecated-by"`
		} `xml:"deprecation"`
	} `xml:"cpe23-item"`
}

type CpeList struct {
	CpeItems []CpeItem `xml:"cpe-item"`
}

const cpeDictionaryURL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
