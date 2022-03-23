package file

import "os"

type Metadata struct {
	Mode            os.FileMode
	Type            Type
	UserID          int
	GroupID         int
	LinkDestination string
	Size            int64
	MIMEType        string
}
