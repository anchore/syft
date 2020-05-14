package analyzer

var controllerInstance controller

func init() {
	controllerInstance = controller{
		analyzers: make([]Analyzer, 0),
	}
}

type controller struct {
	analyzers []Analyzer
}

func (c *controller) add(a Analyzer) {
	c.analyzers = append(c.analyzers, a)
}

func Add(a Analyzer) {
	controllerInstance.add(a)
}