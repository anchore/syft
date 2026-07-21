package main

import "github.com/anchore/archiver/v3"

func main() {

	z := archiver.Zip{
		MkdirAll:               true,
		SelectiveCompression:   true,
		ContinueOnError:        false,
		OverwriteExisting:      false,
		ImplicitTopLevelFolder: false,
	}

	err := z.Archive([]string{"main.go"}, "test.zip")
	if err != nil {
		panic(err)
	}
}
