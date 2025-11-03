package ai

import (
	"fmt"
	"os"
	
	gguf_parser "github.com/gpustack/gguf-parser-go"
)

func main() {
	// Create a test GGUF file
	data := newTestGGUFBuilder().
		withVersion(3).
		withStringKV("general.architecture", "llama").
		withStringKV("general.name", "test-model").
		build()
	
	// Write to temp file
	tempFile, err := os.CreateTemp("", "test-*.gguf")
	if err != nil {
		panic(err)
	}
	defer os.Remove(tempFile.Name())
	
	if _, err := tempFile.Write(data); err != nil {
		panic(err)
	}
	tempFile.Close()
	
	fmt.Printf("Wrote %d bytes to %s\n", len(data), tempFile.Name())
	
	// Try to parse it
	fmt.Println("Attempting to parse...")
	gf, err := gguf_parser.ParseGGUFFile(tempFile.Name(), gguf_parser.SkipLargeMetadata())
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}
	
	fmt.Printf("Success! Model: %s\n", gf.Metadata().Name)
}
