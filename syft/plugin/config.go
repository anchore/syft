package plugin

type Config struct {
	Name    string
	Type    Type
	Command string
	Args    []string
	Env     []string
	//Sha256  []byte
}
