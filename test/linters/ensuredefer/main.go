package ensuredefer

import (
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(NewAnalyzer())
}
