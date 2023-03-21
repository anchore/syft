package license

type Type string

const (
	Declared  Type = "declared"
	Concluded Type = "concluded"
)

type Evidence struct {
	Confidence int
	Offset     int
	Extent     int
}
