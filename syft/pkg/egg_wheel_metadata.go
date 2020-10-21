package pkg

// EggWheelMetadata represents all captured data for a python egg or wheel package.
type EggWheelMetadata struct {
	Name        string `json:"name" mapstruct:"Name"`
	Version     string `json:"version" mapstruct:"Version"`
	License     string `json:"license" mapstruct:"License"`
	Author      string `json:"author" mapstruct:"Author"`
	AuthorEmail string `json:"authorEmail" mapstruct:"Author-email"`
	Platform    string `json:"platform" mapstruct:"Platform"`
}
