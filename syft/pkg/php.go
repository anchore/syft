package pkg

// PhpComposerInstalledEntry represents a single package entry from a composer v1/v2 "installed.json" files (very similar to composer.lock files).
type PhpComposerInstalledEntry PhpComposerLockEntry

// PhpComposerLockEntry represents a single package entry found from a composer.lock file.
type PhpComposerLockEntry struct {
	Name            string                       `json:"name"`
	Version         string                       `json:"version"`
	Source          PhpComposerExternalReference `json:"source"`
	Dist            PhpComposerExternalReference `json:"dist"`
	Require         map[string]string            `json:"require,omitempty"`
	Provide         map[string]string            `json:"provide,omitempty"`
	RequireDev      map[string]string            `json:"require-dev,omitempty"`
	Suggest         map[string]string            `json:"suggest,omitempty"`
	License         []string                     `json:"license,omitempty"`
	Type            string                       `json:"type,omitempty"`
	NotificationURL string                       `json:"notification-url,omitempty"`
	Bin             []string                     `json:"bin,omitempty"`
	Authors         []PhpComposerAuthors         `json:"authors,omitempty"`
	Description     string                       `json:"description,omitempty"`
	Homepage        string                       `json:"homepage,omitempty"`
	Keywords        []string                     `json:"keywords,omitempty"`
	Time            string                       `json:"time,omitempty"`
}

type PhpComposerExternalReference struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum,omitempty"`
}

type PhpComposerAuthors struct {
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	Homepage string `json:"homepage,omitempty"`
}

type PhpPeclEntry struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License []string `json:"license,omitempty"`
}
