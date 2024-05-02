package ensuredefer

import (
	"fmt"
	"go/ast"
	"strings"

	"github.com/golangci/plugin-module-register/register"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

func init() {
	register.Plugin("ensuredefer", func(conf any) (register.LinterPlugin, error) {
		m, ok := conf.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected map[string]any but got %+v (%T)", conf, conf)
		}

		var toCheck []mustDeferSymbol
		symbols := m["symbols"]
		if symbols != nil {
			s, ok := symbols.([]any)
			if !ok {
				return nil, fmt.Errorf("expected slice but got %v (%T)", symbols, symbols)
			}
			for _, maybeSym := range s {
				sym, ok := maybeSym.(string)
				if !ok {
					return nil, fmt.Errorf("expect slice of string but found %v (%T)", maybeSym, maybeSym)
				}

				splitAt := strings.LastIndex(sym, ".")
				if splitAt == -1 {
					return nil, fmt.Errorf("symbols must have form example.com/some/package.SomeMethod, but got %s", sym)
				}
				toCheck = append(toCheck, mustDeferSymbol{
					pkg:     sym[:splitAt],
					funName: sym[splitAt+1:],
				})
			}
		}

		return &analyzerPlugin{
			symbols: toCheck,
		}, nil
	})
}

func makeRun(toCheck map[string]mustDeferSymbol) func(pass *analysis.Pass) (any, error) {
	return func(pass *analysis.Pass) (any, error) {
		insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
		nodeFilter := []ast.Node{
			(*ast.ExprStmt)(nil),
		}
		insp.Preorder(nodeFilter, func(node ast.Node) {
			// if we have a *ast.ExprStmt that calls internal.CloseAndLogError, report a problem.
			// (if the function is correctly called in a defer statement, the statement will have type
			// *ast.DeferStmt.)
			if t, ok := node.(*ast.ExprStmt); ok {
				if !isExprStmtAllowed(t, pass, toCheck) {
					pass.Reportf(t.Pos(), "internal.CloseAndLogError must be called in defer")
				}
			}
		})
		return nil, nil
	}
}

func isExprStmtAllowed(e *ast.ExprStmt, pass *analysis.Pass, toCheck map[string]mustDeferSymbol) bool {
	call, ok := e.X.(*ast.CallExpr)
	if !ok {
		return true
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return true
	}
	candidate, ok := toCheck[sel.Sel.Name]
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

	if pkg.Path() == candidate.pkg && sel.Sel.Name == candidate.funName {
		return false
	}

	return true
}

type mustDeferSymbol struct {
	pkg     string
	funName string
}

type analyzerPlugin struct {
	symbols []mustDeferSymbol
}

func (p *analyzerPlugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	analyzer := &analysis.Analyzer{
		Name:     "ensuredefer",
		Doc:      "enforce that specified functions are called in defer statements",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
	}

	callsToCheck := make(map[string]mustDeferSymbol)
	for _, s := range p.symbols {
		callsToCheck[s.funName] = s
	}
	analyzer.Run = makeRun(callsToCheck)

	return []*analysis.Analyzer{
		analyzer,
	}, nil
}

func (p *analyzerPlugin) GetLoadMode() string {
	return register.LoadModeSyntax
}
