// This program downloads the latest CPE dictionary from NIST and processes it into a JSON file that can be embedded into Syft for more accurate CPE results.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func mainE() error {
	var outputFilename string
	flag.StringVar(&outputFilename, "o", "", "file location to save CPE index")
	flag.Parse()

	if outputFilename == "" {
		return errors.New("-o is required")
	}

	// Download and decompress file
	fmt.Println("Fetching CPE dictionary...")
	resp, err := http.Get(cpeDictionaryURL)
	if err != nil {
		return fmt.Errorf("unable to get CPE dictionary: %w", err)
	}
	defer resp.Body.Close()

	fmt.Println("Generating index...")
	dictionaryJSON, err := generateIndexedDictionaryJSON(resp.Body)
	if err != nil {
		return err
	}

	// Write CPE index (JSON data) to disk
	err = os.WriteFile(outputFilename, dictionaryJSON, 0600)
	if err != nil {
		return fmt.Errorf("unable to write processed CPE dictionary to file: %w", err)
	}

	fmt.Println("Done!")

	return nil
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
