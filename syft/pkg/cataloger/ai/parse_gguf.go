package ai

import (
	"encoding/binary"
	"fmt"
	"io"

	gguf_parser "github.com/gpustack/gguf-parser-go"
)

// GGUF file format constants
const (
	ggufMagicNumber = 0x46554747       // "GGUF" in little-endian
	maxHeaderSize   = 50 * 1024 * 1024 // 50MB for large tokenizer vocabularies
)

// copyHeader copies the GGUF header from the reader to the writer.
// It validates the magic number first, then copies the rest of the data.
// The reader should be wrapped with io.LimitedReader to prevent OOM issues.
func copyHeader(w io.Writer, r io.Reader) error {
	// Read initial chunk to validate magic number
	// GGUF format: magic(4) + version(4) + tensor_count(8) + metadata_kv_count(8) + metadata_kvs + tensors_info
	initialBuf := make([]byte, 24) // Enough for magic, version, tensor count, and kv count
	if _, err := io.ReadFull(r, initialBuf); err != nil {
		return fmt.Errorf("failed to read GGUF header prefix: %w", err)
	}

	// Verify magic number
	magic := binary.LittleEndian.Uint32(initialBuf[0:4])
	if magic != ggufMagicNumber {
		return fmt.Errorf("invalid GGUF magic number: 0x%08X", magic)
	}

	// Write the initial buffer to the writer
	if _, err := w.Write(initialBuf); err != nil {
		return fmt.Errorf("failed to write GGUF header prefix: %w", err)
	}

	// Copy the rest of the header from reader to writer
	// The LimitedReader will return EOF once maxHeaderSize is reached
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("failed to copy GGUF header: %w", err)
	}

	return nil
}

// Helper to convert gguf_parser metadata to simpler types
func convertGGUFMetadataKVs(kvs gguf_parser.GGUFMetadataKVs) map[string]interface{} {
	result := make(map[string]interface{})

	for _, kv := range kvs {
		// Skip standard fields that are extracted separately
		switch kv.Key {
		case "general.architecture", "general.name", "general.license",
			"general.version", "general.parameter_count", "general.quantization":
			continue
		}
		result[kv.Key] = kv.Value
	}

	return result
}
