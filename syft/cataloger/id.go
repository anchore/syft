package cataloger

const (
	ApkDBID                 ID = "os-apkdb"
	DpkgID                  ID = "os-dpkg"
	RpmDBID                 ID = "os-rpmdb"
	RubyGemspecID           ID = "ruby-gem-spec"
	RubyGemfileLockID       ID = "ruby-gem-file-lock"
	PythonPackageID         ID = "python-package"
	PythonRequirementsID    ID = "python-requirements"
	PythonPoetryID          ID = "python-poetry"
	PythonSetupID           ID = "python-setup"
	PythonPipFileID         ID = "python-pipfile"
	JavascriptPackageJSONID ID = "javascript-package-json"
	JavascriptPackageLockID ID = "javascript-package-lock"
	JavaScriptYarnLockID    ID = "javascript-yarn-lock"
	JavaArchiveID           ID = "java-archive"
	GoModID                 ID = "go-mod"
	GoBinaryID              ID = "go-binary"
	RustCargoLockID         ID = "rust-cargo-lock"
	PHPInstalledJSONID      ID = "php-installed-json"
	PHPComposerLockID       ID = "php-composer-lock"

	FileMetadataID   ID = "file-metadata"
	FileDigestsID    ID = "file-digest"
	SecretsID        ID = "secrets"
	FileClassifierID ID = "file-classifier"
	FileContentsID   ID = "file-content"
)

type ID string
type IDs []ID

func (c IDs) Len() int { return len(c) }

func (c IDs) Swap(i, j int) { c[i], c[j] = c[j], c[i] }

func (c IDs) Less(i, j int) bool {
	return c[i] < c[j]
}
