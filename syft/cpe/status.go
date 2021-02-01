package cpe

import "time"

type Status struct {
	Date     time.Time
	Entries  uint64
	Location string
	Err      error
}
