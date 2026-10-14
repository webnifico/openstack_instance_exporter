package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type sourceFunctionDecl struct {
	name string
	file string
	line int
}

func parseGoFilesForDeadCodeContract(t *testing.T, includeTests bool) ([]*ast.File, *token.FileSet, map[string]string) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	paths := make(map[string]string)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || (!includeTests && strings.HasSuffix(name, "_test.go")) {
			continue
		}
		parsed, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, parsed)
		paths[parsed.Name.Name+":"+name] = name
	}
	return files, fset, paths
}

func TestProductionSourceHasNoZeroReferenceUnexportedFunctions(t *testing.T) {
	files, fset, _ := parseGoFilesForDeadCodeContract(t, false)
	var decls []sourceFunctionDecl
	uses := make(map[string]int)

	for _, file := range files {
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			name := fn.Name.Name
			if name == "main" || name == "init" || ast.IsExported(name) {
				continue
			}
			pos := fset.Position(fn.Name.Pos())
			decls = append(decls, sourceFunctionDecl{name: name, file: filepath.Base(pos.Filename), line: pos.Line})
		}
	}

	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				switch call := value.Fun.(type) {
				case *ast.Ident:
					uses[call.Name]++
				case *ast.SelectorExpr:
					uses[call.Sel.Name]++
				}
			case *ast.Ident:
				// Function values and callbacks need not appear directly in CallExpr.
				uses[value.Name]++
			case *ast.SelectorExpr:
				uses[value.Sel.Name]++
			}
			return true
		})
	}

	var dead []string
	for _, decl := range decls {
		// The declaration identifier itself contributes one Ident occurrence.
		// Selector uses are also visited through their Sel Ident, so a real
		// method reference contributes at least two additional observations.
		if uses[decl.name] <= 1 {
			dead = append(dead, decl.file+":"+itoaForDeadCodeContract(decl.line)+" "+decl.name)
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Fatalf("unreferenced unexported production functions remain:\n%s", strings.Join(dead, "\n"))
	}
}

func TestInternalTestAdaptersRemainUsed(t *testing.T) {
	const adapterFile = "internal_test_adapters_test.go"
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, adapterFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := make(map[string]struct{})
	for _, declaration := range parsed.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name != nil {
			declared[fn.Name.Name] = struct{}{}
		}
	}

	used := make(map[string]int)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == adapterFile || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				if _, tracked := declared[ident.Name]; tracked {
					used[ident.Name]++
				}
			}
			return true
		})
	}

	var unused []string
	for name := range declared {
		if used[name] == 0 {
			unused = append(unused, name)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		t.Fatalf("unused test-only adapters remain: %s", strings.Join(unused, ", "))
	}
}

func itoaForDeadCodeContract(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
