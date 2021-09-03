package cpe

import "strings"

func stripEmailSuffix(email string) string {
	return strings.Split(email, "@")[0]
}

func normalizePersonName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	for _, value := range []string{"-", " ", "."} {
		name = strings.ReplaceAll(name, value, "_")
	}
	return strings.TrimPrefix(name, "the_")
}

func normalizeName(name string) string {
	name = strings.Split(name, ",")[0]
	name = strings.TrimSpace(strings.ToLower(name))
	return strings.ReplaceAll(name, " ", "")
}
