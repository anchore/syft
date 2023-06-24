package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generateIndexedDictionaryJSON(t *testing.T) {
	f, err := os.Open("testdata/official-cpe-dictionary_v2.3.xml")
	require.NoError(t, err)

	// Create a buffer to store the gzipped data in memory
	buf := new(bytes.Buffer)

	w := gzip.NewWriter(buf)
	_, err = io.Copy(w, f)
	require.NoError(t, err)

	// (finalize the gzip stream)
	err = w.Close()
	require.NoError(t, err)

	dictionaryJSON, err := generateIndexedDictionaryJSON(buf)
	assert.NoError(t, err)

	expected, err := os.ReadFile("./testdata/expected-cpe-index.json")
	require.NoError(t, err)

	expectedDictionaryJSONString := string(expected)
	dictionaryJSONString := string(dictionaryJSON)

	if diff := cmp.Diff(expectedDictionaryJSONString, dictionaryJSONString); diff != "" {
		t.Errorf("generateIndexedDictionaryJSON() mismatch (-want +got):\n%s", diff)
	}
}
