package main

import (
	"fmt"
	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"log"
	"os"
)

func ReadFilesystem(p string) {
	// Open the squash file
	f, err := os.Open(p)
	if err != nil {
		log.Panic(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		log.Panic(err)
	}

	b := file.New(f, true)
	// create the filesystem
	fs, err := squashfs.Read(b, fi.Size(), 0, 0)
	if err != nil {
		log.Panic(err)
	}

	files, err := fs.ReadDir("/") // this should list everything
	if err != nil {
		log.Panic(err)
	}
	for _, fi := range files {
		fmt.Printf("file: %s\n", fi.Name())
	}
}

func main() {
	ReadFilesystem("/Users/wagoodman/OrbStack/ubuntu/home/wagoodman/snaps/contents/etcd-beta/etcd.snap")
}
