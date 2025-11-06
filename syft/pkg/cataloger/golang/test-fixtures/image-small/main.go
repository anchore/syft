package main

import (
	"context"
	"os"

	"github.com/mholt/archives"
)

func main() {
	// Create a zip archive using the new mholt/archives library
	out, err := os.Create("test.zip")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	format := archives.Zip{}
	files, err := archives.FilesFromDisk(context.Background(), nil, map[string]string{
		"main.go": "main.go",
	})
	if err != nil {
		panic(err)
	}

	err = format.Archive(context.Background(), out, files)
	if err != nil {
		panic(err)
	}
}
