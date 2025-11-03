package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const cacheDir = ".cpe-cache"

// IncrementMetadata tracks a single fetch increment for a monthly batch
type IncrementMetadata struct {
	FetchedAt        time.Time `json:"fetchedAt"`
	LastModStartDate time.Time `json:"lastModStartDate"`
	LastModEndDate   time.Time `json:"lastModEndDate"`
	Products         int       `json:"products"`
	StartIndex       int       `json:"startIndex"` // API pagination start index
	EndIndex         int       `json:"endIndex"`   // API pagination end index (last fetched)
}

// MonthlyBatchMetadata tracks all increments for a specific month
type MonthlyBatchMetadata struct {
	Complete      bool                `json:"complete"`
	TotalProducts int                 `json:"totalProducts"`
	Increments    []IncrementMetadata `json:"increments"`
}

// CacheMetadata tracks the state of the CPE cache using monthly time-based organization
type CacheMetadata struct {
	LastFullRefresh time.Time                        `json:"lastFullRefresh"`
	LastStartIndex  int                              `json:"lastStartIndex"` // last successfully processed startIndex for resume
	TotalProducts   int                              `json:"totalProducts"`
	MonthlyBatches  map[string]*MonthlyBatchMetadata `json:"monthlyBatches"` // key is "YYYY-MM"
}

// CacheManager handles local caching of CPE data
type CacheManager struct {
	cacheDir string
}

// NewCacheManager creates a new cache manager
func NewCacheManager() *CacheManager {
	return &CacheManager{
		cacheDir: cacheDir,
	}
}

// EnsureCacheDir ensures the cache directory exists
func (m *CacheManager) EnsureCacheDir() error {
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	return nil
}

// LoadMetadata loads the cache metadata
func (m *CacheManager) LoadMetadata() (*CacheMetadata, error) {
	metadataPath := filepath.Join(m.cacheDir, "metadata.json")

	// check if metadata file exists
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		// return empty metadata for first run
		return &CacheMetadata{
			LastFullRefresh: time.Time{},
			TotalProducts:   0,
			MonthlyBatches:  make(map[string]*MonthlyBatchMetadata),
		}, nil
	}

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	var metadata CacheMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// ensure MonthlyBatches map is initialized
	if metadata.MonthlyBatches == nil {
		metadata.MonthlyBatches = make(map[string]*MonthlyBatchMetadata)
	}

	return &metadata, nil
}

// SaveMetadata saves the cache metadata
func (m *CacheManager) SaveMetadata(metadata *CacheMetadata) error {
	if err := m.EnsureCacheDir(); err != nil {
		return err
	}

	metadataPath := filepath.Join(m.cacheDir, "metadata.json")

	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(metadataPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	return nil
}

// SaveProductsToMonthlyFile saves products to a monthly file (initial.json or YYYY-MM.json)
// uses atomic write pattern with temp file + rename for safety
func (m *CacheManager) SaveProductsToMonthlyFile(filename string, products []NVDProduct) error {
	if err := m.EnsureCacheDir(); err != nil {
		return err
	}

	filePath := filepath.Join(m.cacheDir, filename)
	tempPath := filePath + ".tmp"

	// marshal products to JSON
	data, err := json.MarshalIndent(products, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal products: %w", err)
	}

	// write to temp file first
	if err := os.WriteFile(tempPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// atomic rename
	if err := os.Rename(tempPath, filePath); err != nil {
		// cleanup temp file on error
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// LoadMonthlyFile loads products from a monthly file
func (m *CacheManager) LoadMonthlyFile(filename string) ([]NVDProduct, error) {
	filePath := filepath.Join(m.cacheDir, filename)

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []NVDProduct{}, nil
		}
		return nil, fmt.Errorf("failed to read %s: %w", filename, err)
	}

	var products []NVDProduct
	if err := json.Unmarshal(data, &products); err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s: %w", filename, err)
	}

	return products, nil
}

// GetMonthKey returns the "YYYY-MM" key for a given time
func GetMonthKey(t time.Time) string {
	return t.Format("2006-01")
}

// SaveProducts saves products grouped by modification month
// this is called after fetching from the API to organize products into monthly files
func (m *CacheManager) SaveProducts(products []NVDProduct, isFullRefresh bool, metadata *CacheMetadata, increment IncrementMetadata) error {
	if len(products) == 0 {
		return nil
	}

	if isFullRefresh {
		return m.saveFullRefresh(products, metadata)
	}

	return m.saveIncrementalUpdate(products, metadata, increment)
}

// saveFullRefresh saves all products to initial.json
func (m *CacheManager) saveFullRefresh(products []NVDProduct, metadata *CacheMetadata) error {
	if err := m.SaveProductsToMonthlyFile("initial.json", products); err != nil {
		return fmt.Errorf("failed to save initial.json: %w", err)
	}

	metadata.LastFullRefresh = time.Now()
	metadata.TotalProducts = len(products)
	metadata.LastStartIndex = 0 // reset on full refresh
	metadata.MonthlyBatches = make(map[string]*MonthlyBatchMetadata)

	return nil
}

// saveIncrementalUpdate saves products grouped by modification month to monthly files
func (m *CacheManager) saveIncrementalUpdate(products []NVDProduct, metadata *CacheMetadata, increment IncrementMetadata) error {
	productsByMonth, err := groupProductsByMonth(products)
	if err != nil {
		return err
	}

	for monthKey, monthProducts := range productsByMonth {
		if err := m.saveMonthlyBatch(monthKey, monthProducts, metadata, increment); err != nil {
			return err
		}
	}

	// update last processed index for resume capability
	metadata.LastStartIndex = increment.EndIndex

	return nil
}

// groupProductsByMonth groups products by their lastModified month
func groupProductsByMonth(products []NVDProduct) (map[string][]NVDProduct, error) {
	productsByMonth := make(map[string][]NVDProduct)

	for _, product := range products {
		lastMod, err := time.Parse(time.RFC3339, product.CPE.LastModified)
		if err != nil {
			return nil, fmt.Errorf("failed to parse lastModified for %s: %w", product.CPE.CPENameID, err)
		}

		monthKey := GetMonthKey(lastMod)
		productsByMonth[monthKey] = append(productsByMonth[monthKey], product)
	}

	return productsByMonth, nil
}

// saveMonthlyBatch saves products for a specific month, merging with existing data
func (m *CacheManager) saveMonthlyBatch(monthKey string, monthProducts []NVDProduct, metadata *CacheMetadata, increment IncrementMetadata) error {
	filename := monthKey + ".json"

	// load existing products for this month
	existing, err := m.LoadMonthlyFile(filename)
	if err != nil {
		return fmt.Errorf("failed to load existing %s: %w", filename, err)
	}

	// merge products (newer wins)
	merged := mergeProducts(existing, monthProducts)

	// atomically save merged products
	if err := m.SaveProductsToMonthlyFile(filename, merged); err != nil {
		return fmt.Errorf("failed to save %s: %w", filename, err)
	}

	// update metadata
	updateMonthlyBatchMetadata(metadata, monthKey, monthProducts, merged, increment)

	return nil
}

// mergeProducts deduplicates products by CPENameID, with newer products overwriting older ones
func mergeProducts(existing, updated []NVDProduct) []NVDProduct {
	productMap := make(map[string]NVDProduct)

	for _, p := range existing {
		productMap[p.CPE.CPENameID] = p
	}
	for _, p := range updated {
		productMap[p.CPE.CPENameID] = p
	}

	merged := make([]NVDProduct, 0, len(productMap))
	for _, p := range productMap {
		merged = append(merged, p)
	}

	return merged
}

// updateMonthlyBatchMetadata updates the metadata for a monthly batch
func updateMonthlyBatchMetadata(metadata *CacheMetadata, monthKey string, newProducts, allProducts []NVDProduct, increment IncrementMetadata) {
	if metadata.MonthlyBatches[monthKey] == nil {
		metadata.MonthlyBatches[monthKey] = &MonthlyBatchMetadata{
			Complete:   false,
			Increments: []IncrementMetadata{},
		}
	}

	batchMeta := metadata.MonthlyBatches[monthKey]
	batchMeta.Increments = append(batchMeta.Increments, IncrementMetadata{
		FetchedAt:        increment.FetchedAt,
		LastModStartDate: increment.LastModStartDate,
		LastModEndDate:   increment.LastModEndDate,
		Products:         len(newProducts),
		StartIndex:       increment.StartIndex,
		EndIndex:         increment.EndIndex,
	})
	batchMeta.TotalProducts = len(allProducts)
}

// LoadAllProducts loads and merges all cached products from monthly files
// returns a deduplicated slice of products (newer products override older ones by CPENameID)
func (m *CacheManager) LoadAllProducts() ([]NVDProduct, error) {
	// check if cache directory exists
	if _, err := os.Stat(m.cacheDir); os.IsNotExist(err) {
		return []NVDProduct{}, nil
	}

	productMap := make(map[string]NVDProduct)

	// load initial.json first (if it exists)
	initial, err := m.LoadMonthlyFile("initial.json")
	if err != nil {
		return nil, fmt.Errorf("failed to load initial.json: %w", err)
	}

	for _, p := range initial {
		productMap[p.CPE.CPENameID] = p
	}

	// load all monthly files (YYYY-MM.json)
	entries, err := os.ReadDir(m.cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// skip metadata.json and initial.json
		if entry.Name() == "metadata.json" || entry.Name() == "initial.json" {
			continue
		}

		// load monthly file
		products, err := m.LoadMonthlyFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", entry.Name(), err)
		}

		// merge products (newer wins based on lastModified)
		for _, p := range products {
			existing, exists := productMap[p.CPE.CPENameID]
			if !exists {
				productMap[p.CPE.CPENameID] = p
				continue
			}

			// compare lastModified timestamps to keep the newer one
			newMod, _ := time.Parse(time.RFC3339, p.CPE.LastModified)
			existingMod, _ := time.Parse(time.RFC3339, existing.CPE.LastModified)

			if newMod.After(existingMod) {
				productMap[p.CPE.CPENameID] = p
			}
		}
	}

	// convert map to slice
	allProducts := make([]NVDProduct, 0, len(productMap))
	for _, p := range productMap {
		allProducts = append(allProducts, p)
	}

	return allProducts, nil
}

// CleanCache removes the local cache directory
func (m *CacheManager) CleanCache() error {
	if err := os.RemoveAll(m.cacheDir); err != nil {
		return fmt.Errorf("failed to clean cache: %w", err)
	}
	fmt.Println("Cache cleaned successfully")
	return nil
}
