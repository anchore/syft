package mimetype

import "github.com/scylladb/go-set/strset"

var (
	ArchiveMIMETypeSet = strset.New(
		// derived from https://en.wikipedia.org/wiki/List_of_archive_formats
		[]string{
			// archive only
			"application/x-archive",
			"application/x-cpio",
			"application/x-shar",
			"application/x-iso9660-image",
			"application/x-sbx",
			"application/x-tar",
			// compression only
			"application/x-bzip2",
			"application/gzip",
			"application/x-lzip",
			"application/x-lzma",
			"application/x-lzop",
			"application/x-snappy-framed",
			"application/x-xz",
			"application/x-compress",
			"application/zstd",
			// archiving and compression
			"application/x-7z-compressed",
			"application/x-ace-compressed",
			"application/x-astrotite-afa",
			"application/x-alz-compressed",
			"application/vnd.android.package-archive",
			"application/x-freearc",
			"application/x-arj",
			"application/x-b1",
			"application/vnd.ms-cab-compressed",
			"application/x-cfs-compressed",
			"application/x-dar",
			"application/x-dgc-compressed",
			"application/x-apple-diskimage",
			"application/x-gca-compressed",
			"application/java-archive",
			"application/x-lzh",
			"application/x-lzx",
			"application/x-rar-compressed",
			"application/x-stuffit",
			"application/x-stuffitx",
			"application/x-gtar",
			"application/x-ms-wim",
			"application/x-xar",
			"application/zip",
			"application/x-zoo",
		}...,
	)

	ExecutableMIMETypeSet = strset.New(
		[]string{
			"application/x-executable",
			"application/x-mach-binary",
			"application/x-elf",
			"application/x-sharedlib",
			"application/vnd.microsoft.portable-executable",
			"application/x-executable",
		}...,
	)
)

func IsArchive(mimeType string) bool {
	return ArchiveMIMETypeSet.Has(mimeType)
}

func IsExecutable(mimeType string) bool {
	return ExecutableMIMETypeSet.Has(mimeType)
}
