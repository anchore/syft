package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheManager_MonthlyFileOperations(t *testing.T) {
	tmpDir := t.TempDir()
	cacheManager := &CacheManager{cacheDir: tmpDir}

	testProducts := []NVDProduct{
		{
			CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product1:1.0:*:*:*:*:*:*:*",
				CPENameID:    "product1-id",
				LastModified: "2024-11-15T10:00:00.000Z",
				Titles:       []NVDTitle{{Title: "Test Product 1", Lang: "en"}},
			},
		},
		{
			CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product2:2.0:*:*:*:*:*:*:*",
				CPENameID:    "product2-id",
				LastModified: "2024-11-20T10:00:00.000Z",
				Titles:       []NVDTitle{{Title: "Test Product 2", Lang: "en"}},
			},
		},
	}

	t.Run("save and load monthly file", func(t *testing.T) {
		err := cacheManager.SaveProductsToMonthlyFile("2024-11.json", testProducts)
		require.NoError(t, err)

		expectedPath := filepath.Join(tmpDir, "2024-11.json")
		require.FileExists(t, expectedPath)

		loaded, err := cacheManager.LoadMonthlyFile("2024-11.json")
		require.NoError(t, err)
		require.Len(t, loaded, 2)
		assert.Equal(t, testProducts[0].CPE.CPEName, loaded[0].CPE.CPEName)
		assert.Equal(t, testProducts[1].CPE.CPEName, loaded[1].CPE.CPEName)
	})

	t.Run("atomic save with temp file", func(t *testing.T) {
		err := cacheManager.SaveProductsToMonthlyFile("2024-12.json", testProducts)
		require.NoError(t, err)

		// temp file should not exist after successful save
		tempPath := filepath.Join(tmpDir, "2024-12.json.tmp")
		require.NoFileExists(t, tempPath)

		// actual file should exist
		finalPath := filepath.Join(tmpDir, "2024-12.json")
		require.FileExists(t, finalPath)
	})

	t.Run("load non-existent file returns empty", func(t *testing.T) {
		loaded, err := cacheManager.LoadMonthlyFile("2025-01.json")
		require.NoError(t, err)
		assert.Empty(t, loaded)
	})
}

func TestCacheManager_Metadata(t *testing.T) {
	tmpDir := t.TempDir()
	cacheManager := &CacheManager{cacheDir: tmpDir}

	t.Run("load metadata on first run", func(t *testing.T) {
		metadata, err := cacheManager.LoadMetadata()
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.NotNil(t, metadata.MonthlyBatches)
		assert.True(t, metadata.LastFullRefresh.IsZero())
		assert.Equal(t, 0, metadata.LastStartIndex)
		assert.Equal(t, 0, metadata.TotalProducts)
	})

	t.Run("save and load metadata with monthly batches", func(t *testing.T) {
		now := time.Now()
		metadata := &CacheMetadata{
			LastFullRefresh: now,
			LastStartIndex:  4000,
			TotalProducts:   1500,
			MonthlyBatches: map[string]*MonthlyBatchMetadata{
				"2024-11": {
					Complete:      true,
					TotalProducts: 1000,
					Increments: []IncrementMetadata{
						{
							FetchedAt:        now,
							LastModStartDate: now.Add(-24 * time.Hour),
							LastModEndDate:   now,
							Products:         1000,
							StartIndex:       0,
							EndIndex:         2000,
						},
					},
				},
				"2024-12": {
					Complete:      false,
					TotalProducts: 500,
					Increments: []IncrementMetadata{
						{
							FetchedAt:        now,
							LastModStartDate: now.Add(-12 * time.Hour),
							LastModEndDate:   now,
							Products:         500,
							StartIndex:       0,
							EndIndex:         1000,
						},
					},
				},
			},
		}

		err := cacheManager.SaveMetadata(metadata)
		require.NoError(t, err)

		loadedMetadata, err := cacheManager.LoadMetadata()
		require.NoError(t, err)

		assert.Equal(t, metadata.TotalProducts, loadedMetadata.TotalProducts)
		assert.Equal(t, metadata.LastStartIndex, loadedMetadata.LastStartIndex)
		assert.Equal(t, 2, len(loadedMetadata.MonthlyBatches))
		assert.True(t, loadedMetadata.MonthlyBatches["2024-11"].Complete)
		assert.False(t, loadedMetadata.MonthlyBatches["2024-12"].Complete)
		assert.Equal(t, 1000, loadedMetadata.MonthlyBatches["2024-11"].TotalProducts)
		assert.Len(t, loadedMetadata.MonthlyBatches["2024-11"].Increments, 1)
	})
}

func TestCacheManager_LoadAllProducts(t *testing.T) {
	tmpDir := t.TempDir()
	cacheManager := &CacheManager{cacheDir: tmpDir}

	t.Run("load and merge monthly files", func(t *testing.T) {
		// save initial.json with base products
		initialProducts := []NVDProduct{
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product1:*:*:*:*:*:*:*:*",
				CPENameID:    "product1-id",
				LastModified: "2024-10-01T10:00:00.000Z",
			}},
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*",
				CPENameID:    "product2-id",
				LastModified: "2024-10-15T10:00:00.000Z",
			}},
		}
		err := cacheManager.SaveProductsToMonthlyFile("initial.json", initialProducts)
		require.NoError(t, err)

		// save 2024-11.json with updated product2 and new product3
		novemberProducts := []NVDProduct{
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*",
				CPENameID:    "product2-id",
				LastModified: "2024-11-05T10:00:00.000Z", // newer version
			}},
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product3:*:*:*:*:*:*:*:*",
				CPENameID:    "product3-id",
				LastModified: "2024-11-10T10:00:00.000Z",
			}},
		}
		err = cacheManager.SaveProductsToMonthlyFile("2024-11.json", novemberProducts)
		require.NoError(t, err)

		// load all products
		allProducts, err := cacheManager.LoadAllProducts()
		require.NoError(t, err)

		// should have 3 unique products (product2 from Nov overwrites Oct version)
		require.Len(t, allProducts, 3)

		// verify we got all products
		cpeNames := make(map[string]string) // CPENameID -> LastModified
		for _, product := range allProducts {
			cpeNames[product.CPE.CPENameID] = product.CPE.LastModified
		}

		assert.Contains(t, cpeNames, "product1-id")
		assert.Contains(t, cpeNames, "product2-id")
		assert.Contains(t, cpeNames, "product3-id")

		// product2 should be the newer version from November
		assert.Equal(t, "2024-11-05T10:00:00.000Z", cpeNames["product2-id"])
	})

	t.Run("empty directory", func(t *testing.T) {
		emptyDir := t.TempDir()
		emptyCache := &CacheManager{cacheDir: emptyDir}

		allProducts, err := emptyCache.LoadAllProducts()
		require.NoError(t, err)
		assert.Empty(t, allProducts)
	})
}

func TestCacheManager_CleanCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheManager := &CacheManager{cacheDir: tmpDir}

	// create some cache files
	testProducts := []NVDProduct{
		{CPE: NVDProductDetails{
			CPEName:      "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			CPENameID:    "test-id",
			LastModified: "2024-11-01T10:00:00.000Z",
		}},
	}
	err := cacheManager.SaveProductsToMonthlyFile("initial.json", testProducts)
	require.NoError(t, err)

	// verify cache exists
	require.DirExists(t, tmpDir)

	// clean cache
	err = cacheManager.CleanCache()
	require.NoError(t, err)

	// verify cache is removed
	_, err = os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(err))
}

func TestCacheManager_SaveProducts(t *testing.T) {
	tmpDir := t.TempDir()
	cacheManager := &CacheManager{cacheDir: tmpDir}

	t.Run("full refresh saves to initial.json", func(t *testing.T) {
		metadata := &CacheMetadata{
			MonthlyBatches: make(map[string]*MonthlyBatchMetadata),
		}

		products := []NVDProduct{
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product1:*:*:*:*:*:*:*:*",
				CPENameID:    "p1",
				LastModified: "2024-10-01T10:00:00.000Z",
			}},
		}

		increment := IncrementMetadata{
			FetchedAt: time.Now(),
			Products:  1,
		}

		err := cacheManager.SaveProducts(products, true, metadata, increment)
		require.NoError(t, err)

		// verify initial.json exists
		initialPath := filepath.Join(tmpDir, "initial.json")
		require.FileExists(t, initialPath)

		// verify metadata updated
		assert.NotZero(t, metadata.LastFullRefresh)
		assert.Equal(t, 1, metadata.TotalProducts)
		assert.Empty(t, metadata.MonthlyBatches)
	})

	t.Run("incremental update groups by month", func(t *testing.T) {
		metadata := &CacheMetadata{
			LastFullRefresh: time.Now().Add(-30 * 24 * time.Hour),
			MonthlyBatches:  make(map[string]*MonthlyBatchMetadata),
		}

		products := []NVDProduct{
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product1:*:*:*:*:*:*:*:*",
				CPENameID:    "p1",
				LastModified: "2024-11-05T10:00:00.000Z",
			}},
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*",
				CPENameID:    "p2",
				LastModified: "2024-11-15T10:00:00.000Z",
			}},
			{CPE: NVDProductDetails{
				CPEName:      "cpe:2.3:a:vendor:product3:*:*:*:*:*:*:*:*",
				CPENameID:    "p3",
				LastModified: "2024-12-01T10:00:00.000Z",
			}},
		}

		increment := IncrementMetadata{
			FetchedAt: time.Now(),
			Products:  3,
		}

		err := cacheManager.SaveProducts(products, false, metadata, increment)
		require.NoError(t, err)

		// verify monthly files exist
		nov2024Path := filepath.Join(tmpDir, "2024-11.json")
		dec2024Path := filepath.Join(tmpDir, "2024-12.json")
		require.FileExists(t, nov2024Path)
		require.FileExists(t, dec2024Path)

		// verify metadata has monthly batches
		assert.Len(t, metadata.MonthlyBatches, 2)
		assert.Contains(t, metadata.MonthlyBatches, "2024-11")
		assert.Contains(t, metadata.MonthlyBatches, "2024-12")

		// verify 2024-11 has 2 products
		assert.Equal(t, 2, metadata.MonthlyBatches["2024-11"].TotalProducts)
		assert.Len(t, metadata.MonthlyBatches["2024-11"].Increments, 1)

		// verify 2024-12 has 1 product
		assert.Equal(t, 1, metadata.MonthlyBatches["2024-12"].TotalProducts)
	})
}
