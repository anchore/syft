package model

type License struct {
	ID   string `json:"id,omitempty"`   // A valid SPDX license ID
	Name string `json:"name,omitempty"` // If SPDX does not define the license used, this field may be used to provide the license name
}
