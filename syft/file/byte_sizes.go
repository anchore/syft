package file

const (
	// represents the order of bytes
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
)
