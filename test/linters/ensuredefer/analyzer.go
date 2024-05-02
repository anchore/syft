package ensuredefer

import (
	"go/ast"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

func init() {
	register.Plugin("ensuredefer", func(_ any) (register.LinterPlugin, error) {
		return &analyzerPlugin{}, nil
	})
}

func run(pass *analysis.Pass) (any, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeFilter := []ast.Node{
		(*ast.ExprStmt)(nil),
	}
	insp.Preorder(nodeFilter, func(node ast.Node) {
		// if we have a *ast.ExprStmt that calls internal.CloseAndLogError, report a problem.
		// (if the function is correctly called in a defer statement, the block will have
		if t, ok := node.(*ast.ExprStmt); ok {
			if !isExprStmtAllowed(t, pass) {
				pass.Reportf(t.Pos(), "internal.CloseAndLogError must be called in defer")
			}
		}
	})
	return nil, nil
}

func isExprStmtAllowed(e *ast.ExprStmt, pass *analysis.Pass) bool {
	call, ok := e.X.(*ast.CallExpr)
	if !ok {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return true
	}

	obj := pass.TypesInfo.Uses[sel.Sel]
	if obj == nil {
		return true
	}
	pkg := obj.Pkg()
	if pkg == nil {
		return true
	}

	if pkg.Path() == "github.com/anchore/syft/internal" && sel.Sel.Name == "CloseAndLogError" {
		return false
	}

	return true
}

func NewAnalyzer() *analysis.Analyzer {
	analyzer := analysis.Analyzer{
		Name:     "ensuredefer",
		Doc:      "enforce that specified functions are called in defer statements",
		Run:      run,
		Requires: []*analysis.Analyzer{inspect.Analyzer},
	}
	return &analyzer
}

var analyzerInstance = NewAnalyzer()

type analyzerPlugin struct{}

func (p *analyzerPlugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return []*analysis.Analyzer{
		analyzerInstance,
	}, nil
}

func (p *analyzerPlugin) GetLoadMode() string {
	//TODO: what does this do
	return register.LoadModeSyntax
}
