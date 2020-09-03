package plugin

// repository
type Collection struct {
	byType map[Type]Plugin
	byName map[string]Plugin
}
