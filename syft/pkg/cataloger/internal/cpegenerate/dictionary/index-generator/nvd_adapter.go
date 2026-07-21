package main

// nvd_adapter.go converts NVD API responses to the existing CpeList/CpeItem structures
// this allows the existing filtering and indexing logic to work without modification

// ProductsToCpeList converts NVD API products to the legacy CpeList format
func ProductsToCpeList(products []NVDProduct) CpeList {
	var cpeItems []CpeItem

	for _, product := range products {
		item := productToCpeItem(product)
		cpeItems = append(cpeItems, item)
	}

	return CpeList{
		CpeItems: cpeItems,
	}
}

// productToCpeItem converts a single NVD API product to a CpeItem
func productToCpeItem(product NVDProduct) CpeItem {
	details := product.CPE

	item := CpeItem{
		// use CPE 2.2 format for the Name field (legacy compatibility)
		// note: the old XML feed had both 2.2 and 2.3 formats
		// for now, we'll use 2.3 format in both places since that's what the API provides
		Name: details.CPEName,
	}

	// extract title (prefer English)
	for _, title := range details.Titles {
		if title.Lang == "en" {
			item.Title = title.Title
			break
		}
	}
	// fallback to first title if no English title found
	if item.Title == "" && len(details.Titles) > 0 {
		item.Title = details.Titles[0].Title
	}

	// convert references
	if len(details.Refs) > 0 {
		item.References.Reference = make([]struct {
			Href string `xml:"href,attr"`
			Body string `xml:",chardata"`
		}, len(details.Refs))

		for i, ref := range details.Refs {
			item.References.Reference[i].Href = ref.Ref
			item.References.Reference[i].Body = ref.Type
		}
	}

	// set CPE 2.3 information
	item.Cpe23Item.Name = details.CPEName

	// handle deprecation
	if details.Deprecated && len(details.DeprecatedBy) > 0 {
		// use the first deprecated-by CPE (the old format only supported one)
		item.Cpe23Item.Deprecation.DeprecatedBy.Name = details.DeprecatedBy[0].CPEName
	}

	return item
}
