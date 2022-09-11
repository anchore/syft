package model

type Checksum struct {
	// Identifies the algorithm used to produce the subject Checksum. One of: "SHA256", "SHA1", "SHA384", "MD2", "MD4", "SHA512", "MD6", "MD5", "SHA224"
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
