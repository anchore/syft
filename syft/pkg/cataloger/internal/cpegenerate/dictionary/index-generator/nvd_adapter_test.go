package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProductToCpeItem(t *testing.T) {
	tests := []struct {
		name     string
		product  NVDProduct
		expected CpeItem
	}{
		{
			name: "basic product conversion",
			product: NVDProduct{
				CPE: NVDProductDetails{
					CPEName:    "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
					Deprecated: false,
					Titles: []NVDTitle{
						{Title: "Test Product", Lang: "en"},
					},
					Refs: []NVDRef{
						{Ref: "https://example.com/product", Type: "Vendor"},
					},
				},
			},
			expected: CpeItem{
				Name:  "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				Title: "Test Product",
				References: struct {
					Reference []struct {
						Href string `xml:"href,attr"`
						Body string `xml:",chardata"`
					} `xml:"reference"`
				}{
					Reference: []struct {
						Href string `xml:"href,attr"`
						Body string `xml:",chardata"`
					}{
						{Href: "https://example.com/product", Body: "Vendor"},
					},
				},
				Cpe23Item: struct {
					Name        string `xml:"name,attr"`
					Deprecation struct {
						DeprecatedBy struct {
							Name string `xml:"name,attr"`
						} `xml:"deprecated-by"`
					} `xml:"deprecation"`
				}{
					Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				},
			},
		},
		{
			name: "deprecated product",
			product: NVDProduct{
				CPE: NVDProductDetails{
					CPEName:    "cpe:2.3:a:vendor:old:1.0:*:*:*:*:*:*:*",
					Deprecated: true,
					DeprecatedBy: []NVDDeprecatedBy{
						{CPEName: "cpe:2.3:a:vendor:new:1.0:*:*:*:*:*:*:*", CPENameID: "test-uuid-123"},
					},
					Titles: []NVDTitle{
						{Title: "Old Product", Lang: "en"},
					},
					Refs: []NVDRef{
						{Ref: "https://example.com/old", Type: "Vendor"},
					},
				},
			},
			expected: CpeItem{
				Name:  "cpe:2.3:a:vendor:old:1.0:*:*:*:*:*:*:*",
				Title: "Old Product",
				References: struct {
					Reference []struct {
						Href string `xml:"href,attr"`
						Body string `xml:",chardata"`
					} `xml:"reference"`
				}{
					Reference: []struct {
						Href string `xml:"href,attr"`
						Body string `xml:",chardata"`
					}{
						{Href: "https://example.com/old", Body: "Vendor"},
					},
				},
				Cpe23Item: struct {
					Name        string `xml:"name,attr"`
					Deprecation struct {
						DeprecatedBy struct {
							Name string `xml:"name,attr"`
						} `xml:"deprecated-by"`
					} `xml:"deprecation"`
				}{
					Name: "cpe:2.3:a:vendor:old:1.0:*:*:*:*:*:*:*",
					Deprecation: struct {
						DeprecatedBy struct {
							Name string `xml:"name,attr"`
						} `xml:"deprecated-by"`
					}{
						DeprecatedBy: struct {
							Name string `xml:"name,attr"`
						}{
							Name: "cpe:2.3:a:vendor:new:1.0:*:*:*:*:*:*:*",
						},
					},
				},
			},
		},
		{
			name: "product with multiple titles prefers English",
			product: NVDProduct{
				CPE: NVDProductDetails{
					CPEName: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
					Titles: []NVDTitle{
						{Title: "Produit", Lang: "fr"},
						{Title: "Product", Lang: "en"},
						{Title: "Producto", Lang: "es"},
					},
					Refs: []NVDRef{
						{Ref: "https://example.com", Type: "Vendor"},
					},
				},
			},
			expected: CpeItem{
				Name:  "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				Title: "Product",
				References: struct {
					Reference []struct {
						Href string `xml:"href,attr"`
						Body string `xml:",chardata"`
					} `xml:"reference"`
				}{
					Reference: []struct {
						Href string `xml:"href,attr"`
						Body string `xml:",chardata"`
					}{
						{Href: "https://example.com", Body: "Vendor"},
					},
				},
				Cpe23Item: struct {
					Name        string `xml:"name,attr"`
					Deprecation struct {
						DeprecatedBy struct {
							Name string `xml:"name,attr"`
						} `xml:"deprecated-by"`
					} `xml:"deprecation"`
				}{
					Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := productToCpeItem(tt.product)

			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Title, result.Title)
			assert.Equal(t, tt.expected.Cpe23Item.Name, result.Cpe23Item.Name)
			assert.Equal(t, tt.expected.Cpe23Item.Deprecation.DeprecatedBy.Name, result.Cpe23Item.Deprecation.DeprecatedBy.Name)

			require.Equal(t, len(tt.expected.References.Reference), len(result.References.Reference))
			for i := range tt.expected.References.Reference {
				assert.Equal(t, tt.expected.References.Reference[i].Href, result.References.Reference[i].Href)
				assert.Equal(t, tt.expected.References.Reference[i].Body, result.References.Reference[i].Body)
			}
		})
	}
}

func TestProductsToCpeList(t *testing.T) {
	products := []NVDProduct{
		{
			CPE: NVDProductDetails{
				CPEName: "cpe:2.3:a:vendor:product1:1.0:*:*:*:*:*:*:*",
				Titles: []NVDTitle{
					{Title: "Product 1", Lang: "en"},
				},
				Refs: []NVDRef{
					{Ref: "https://npmjs.com/package/product1", Type: "Vendor"},
				},
			},
		},
		{
			CPE: NVDProductDetails{
				CPEName: "cpe:2.3:a:vendor:product2:2.0:*:*:*:*:*:*:*",
				Titles: []NVDTitle{
					{Title: "Product 2", Lang: "en"},
				},
				Refs: []NVDRef{
					{Ref: "https://pypi.org/project/product2", Type: "Vendor"},
				},
			},
		},
	}

	result := ProductsToCpeList(products)

	require.Len(t, result.CpeItems, 2)
	assert.Equal(t, "cpe:2.3:a:vendor:product1:1.0:*:*:*:*:*:*:*", result.CpeItems[0].Name)
	assert.Equal(t, "Product 1", result.CpeItems[0].Title)
	assert.Equal(t, "cpe:2.3:a:vendor:product2:2.0:*:*:*:*:*:*:*", result.CpeItems[1].Name)
	assert.Equal(t, "Product 2", result.CpeItems[1].Title)
}

func TestProductsToCpeList_MultipleProducts(t *testing.T) {
	products := []NVDProduct{
		{
			CPE: NVDProductDetails{
				CPEName: "cpe:2.3:a:vendor:product1:*:*:*:*:*:*:*:*",
				Titles:  []NVDTitle{{Title: "Product 1", Lang: "en"}},
				Refs:    []NVDRef{{Ref: "https://example.com/1", Type: "Vendor"}},
			},
		},
		{
			CPE: NVDProductDetails{
				CPEName: "cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*",
				Titles:  []NVDTitle{{Title: "Product 2", Lang: "en"}},
				Refs:    []NVDRef{{Ref: "https://example.com/2", Type: "Vendor"}},
			},
		},
	}

	result := ProductsToCpeList(products)

	require.Len(t, result.CpeItems, 2)
	assert.Equal(t, "cpe:2.3:a:vendor:product1:*:*:*:*:*:*:*:*", result.CpeItems[0].Cpe23Item.Name)
	assert.Equal(t, "cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*", result.CpeItems[1].Cpe23Item.Name)
}
