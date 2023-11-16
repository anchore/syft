package spdxhelpers

import (
	"strings"
)

func NoneIfEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return NONE
	}
	return value
}
