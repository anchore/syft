package ui

import "fmt"

func RenderError(err error) string {
	return fmt.Sprintf("%s%v%s", red, err, reset)
}
