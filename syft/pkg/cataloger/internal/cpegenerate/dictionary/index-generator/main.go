// This program fetches CPE data from the NVD Products API and processes it into a JSON file that can be embedded into Syft for more accurate CPE results.
// ORAS caching is managed by Taskfile tasks - this program only works with local cache.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

func mainE() error {
	var outputFilename string
	var forceFullRefresh bool
	var cacheOnly bool
	flag.StringVar(&outputFilename, "o", "", "file location to save CPE index (required for build mode)")
	flag.BoolVar(&forceFullRefresh, "full", false, "force full refresh instead of incremental update")
	flag.BoolVar(&cacheOnly, "cache-only", false, "only update cache from NVD API, don't generate index")
	flag.Parse()

	// validate flags
	if !cacheOnly && outputFilename == "" {
		return errors.New("-o is required (unless using -cache-only)")
	}

	if cacheOnly && outputFilename != "" {
		return errors.New("-cache-only and -o cannot be used together")
	}

	ctx := context.Background()
	cacheManager := NewCacheManager()

	// MODE 1: Update cache only (called by task generate:cpe-index:update-cache)
	if cacheOnly {
		return updateCache(ctx, cacheManager, forceFullRefresh)
	}

	// MODE 2: Generate index from existing cache (called by task generate:cpe-index:build)
	return generateIndexFromCache(cacheManager, outputFilename)
}

// updateCache fetches new/updated CPE data from NVD API and saves to local cache
func updateCache(ctx context.Context, cacheManager *CacheManager, forceFullRefresh bool) error {
	metadata, err := cacheManager.LoadMetadata()
	if err != nil {
		return fmt.Errorf("failed to load metadata: %w", err)
	}

	lastModStartDate, isFullRefresh := determineUpdateMode(metadata, forceFullRefresh)

	// use resume index if available
	resumeFromIndex := 0
	if !isFullRefresh && metadata.LastStartIndex > 0 {
		resumeFromIndex = metadata.LastStartIndex
		fmt.Printf("Resuming from index %d...\n", resumeFromIndex)
	}

	allProducts, increment, err := fetchProducts(ctx, lastModStartDate, resumeFromIndex)
	if err != nil {
		// if we have partial products, save them before returning error
		if len(allProducts) > 0 {
			fmt.Printf("\nError occurred but saving %d products fetched so far...\n", len(allProducts))
			if saveErr := saveAndReportResults(cacheManager, allProducts, isFullRefresh, metadata, increment); saveErr != nil {
				fmt.Printf("WARNING: Failed to save partial progress: %v\n", saveErr)
			} else {
				fmt.Println("Partial progress saved successfully. Run again to resume from this point.")
			}
		}
		return err
	}

	if len(allProducts) == 0 {
		fmt.Println("No products fetched (already up to date)")
		return nil
	}

	return saveAndReportResults(cacheManager, allProducts, isFullRefresh, metadata, increment)
}

// determineUpdateMode decides whether to do a full refresh or incremental update
func determineUpdateMode(metadata *CacheMetadata, forceFullRefresh bool) (time.Time, bool) {
	if forceFullRefresh || metadata.LastFullRefresh.IsZero() {
		fmt.Println("Performing full refresh of CPE data")
		return time.Time{}, true
	}

	fmt.Printf("Performing incremental update since %s\n", metadata.LastFullRefresh.Format("2006-01-02"))
	return metadata.LastFullRefresh, false
}

// fetchProducts fetches products from the NVD API
func fetchProducts(ctx context.Context, lastModStartDate time.Time, resumeFromIndex int) ([]NVDProduct, IncrementMetadata, error) {
	apiClient := NewNVDAPIClient()
	fmt.Println("Fetching CPE data from NVD Products API...")

	var allProducts []NVDProduct
	var totalResults int
	var firstStartIndex, lastEndIndex int

	onPageFetched := func(startIndex int, response NVDProductsResponse) error {
		if totalResults == 0 {
			totalResults = response.TotalResults
			firstStartIndex = startIndex
		}
		lastEndIndex = startIndex + response.ResultsPerPage
		allProducts = append(allProducts, response.Products...)
		fmt.Printf("Fetched %d/%d products...\n", len(allProducts), totalResults)
		return nil
	}

	if err := apiClient.FetchProductsSince(ctx, lastModStartDate, resumeFromIndex, onPageFetched); err != nil {
		// return partial products with increment metadata so they can be saved
		increment := IncrementMetadata{
			FetchedAt:        time.Now(),
			LastModStartDate: lastModStartDate,
			LastModEndDate:   time.Now(),
			Products:         len(allProducts),
			StartIndex:       firstStartIndex,
			EndIndex:         lastEndIndex,
		}
		return allProducts, increment, fmt.Errorf("failed to fetch products from NVD API: %w", err)
	}

	increment := IncrementMetadata{
		FetchedAt:        time.Now(),
		LastModStartDate: lastModStartDate,
		LastModEndDate:   time.Now(),
		Products:         len(allProducts),
		StartIndex:       firstStartIndex,
		EndIndex:         lastEndIndex,
	}

	return allProducts, increment, nil
}

// saveAndReportResults saves products and metadata, then reports success
func saveAndReportResults(cacheManager *CacheManager, allProducts []NVDProduct, isFullRefresh bool, metadata *CacheMetadata, increment IncrementMetadata) error {
	fmt.Println("Saving products to cache...")
	if err := cacheManager.SaveProducts(allProducts, isFullRefresh, metadata, increment); err != nil {
		return fmt.Errorf("failed to save products: %w", err)
	}

	if err := cacheManager.SaveMetadata(metadata); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	fmt.Println("Cache updated successfully!")
	if isFullRefresh {
		fmt.Printf("Total products in cache: %d\n", len(allProducts))
	} else {
		fmt.Printf("Added/updated %d products\n", len(allProducts))
		fmt.Printf("Grouped into %d monthly files\n", len(metadata.MonthlyBatches))
	}

	return nil
}

// generateIndexFromCache generates the CPE index from cached data only
func generateIndexFromCache(cacheManager *CacheManager, outputFilename string) error {
	fmt.Println("Loading cached products...")
	allProducts, err := cacheManager.LoadAllProducts()
	if err != nil {
		return fmt.Errorf("failed to load cached products: %w", err)
	}

	if len(allProducts) == 0 {
		return fmt.Errorf("no cached data available - run 'task generate:cpe-index:cache:pull' and 'task generate:cpe-index:cache:update' first")
	}

	fmt.Printf("Loaded %d products from cache\n", len(allProducts))
	fmt.Println("Converting products to CPE list...")
	cpeList := ProductsToCpeList(allProducts)

	fmt.Println("Generating index...")
	dictionaryJSON, err := processCPEList(cpeList)
	if err != nil {
		return err
	}

	// ensure parent directory exists
	outputDir := filepath.Dir(outputFilename)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := os.WriteFile(outputFilename, dictionaryJSON, 0600); err != nil {
		return fmt.Errorf("unable to write processed CPE dictionary to file: %w", err)
	}

	fmt.Println("CPE index generated successfully!")
	return nil
}

// processCPEList filters and indexes a CPE list, returning JSON bytes
func processCPEList(cpeList CpeList) ([]byte, error) {
	// filter out data that's not applicable
	cpeList = filterCpeList(cpeList)

	// create indexed dictionary to help with looking up CPEs
	indexedDictionary := indexCPEList(cpeList)

	// convert to JSON
	jsonData, err := json.MarshalIndent(indexedDictionary, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("unable to marshal CPE dictionary to JSON: %w", err)
	}
	return jsonData, nil
}

// errExit prints an error and exits with a non-zero exit code.
func errExit(err error) {
	log.Printf("command failed: %s", err)
	os.Exit(1)
}

func main() {
	if err := mainE(); err != nil {
		errExit(err)
	}
}
