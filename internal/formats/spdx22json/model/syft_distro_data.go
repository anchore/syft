package model

type SyftDistroData struct {
	Name    string `json:"name"`    // Name of the Linux distribution
	Version string `json:"version"` // Version of the Linux distribution (major or major.minor version)
	IDLike  string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}
