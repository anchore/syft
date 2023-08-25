package pkg

type DotnetPortableExecutableMetadata struct {
	AssemblyVersion string `json:"assemblyVersion"`
	LegalCopyright  string `json:"legalCopyright"`
	Comments        string `json:"comments,omitempty"`
	InternalName    string `json:"internalName,omitempty"`
	CompanyName     string `json:"companyName"`
	ProductName     string `json:"productName"`
	ProductVersion  string `json:"productVersion"`
}
