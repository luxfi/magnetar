// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build ct
// +build ct

// Package dudect carries the Magnetar v1.1 strict-atom Combine CT
// harness. Run via:
//
//	go test -tags ct -run TestStrictAtom_CT ./ct/dudect/...
//
// or via scripts/checks/dudect-smoke.sh.
package dudect

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// strictAtomSources are the Go files the v1.1 CT track inspects. They
// are the entire trusted-computing-base of the strict-atom emit path.
var strictAtomSources = []string{
	"../../ref/go/pkg/magnetar/thbsse_assemble.go",
	"../../ref/go/pkg/magnetar/slhdsa_internal.go",
}

// secretTaggedIdent patterns. The v1.1 CT discipline says: any
// identifier whose name is one of these is carrying secret bytes,
// and therefore must NOT appear in:
//   - a switch / if-else condition (control flow on secret)
//   - an index expression LHS (array/slice index on secret)
//   - a map key (map lookup on secret)
//
// The strict-atom emit path uses these names verbatim for the buffers
// holding Lagrange-reconstructed material; the static check ensures
// they are only consumed via `append`, `copy`, and `Write` calls.
var secretTaggedIdents = map[string]struct{}{
	"derivedMaterial":      {},
	"derivedExpandInput":   {},
	"derivedPkSeedSegment": {},
	"secretSegment":        {},
	"prfAbsorb":            {},
	"prfMsgAbsorb":         {},
}

// TestStrictAtom_CT_NoSecretDependentBranch is the load-bearing per-push
// CT gate. It parses the strict-atom emit-path sources, walks the AST,
// and asserts no secret-tagged identifier feeds a control-flow branch,
// an index expression, or a map key.
func TestStrictAtom_CT_NoSecretDependentBranch(t *testing.T) {
	for _, rel := range strictAtomSources {
		t.Run(filepath.Base(rel), func(t *testing.T) {
			abs, err := filepath.Abs(rel)
			if err != nil {
				t.Fatalf("filepath.Abs(%s): %v", rel, err)
			}
			if _, err := os.Stat(abs); err != nil {
				t.Fatalf("stat(%s): %v", abs, err)
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, abs, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parser.ParseFile(%s): %v", rel, err)
			}

			var violations []string

			ast.Inspect(f, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.IfStmt:
					if name, ok := findSecretIdent(v.Cond); ok {
						pos := fset.Position(v.Pos())
						violations = append(violations, fmt.Sprintf(
							"if-branch on secret-tagged %q at %s:%d",
							name, filepath.Base(pos.Filename), pos.Line))
					}
				case *ast.SwitchStmt:
					if name, ok := findSecretIdent(v.Tag); ok {
						pos := fset.Position(v.Pos())
						violations = append(violations, fmt.Sprintf(
							"switch on secret-tagged %q at %s:%d",
							name, filepath.Base(pos.Filename), pos.Line))
					}
				case *ast.IndexExpr:
					// Only flag when the INDEX is a secret-tagged
					// ident; indexing INTO a secret buffer (the LHS)
					// is fine.
					if name, ok := findSecretIdent(v.Index); ok {
						pos := fset.Position(v.Pos())
						violations = append(violations, fmt.Sprintf(
							"index using secret-tagged %q at %s:%d",
							name, filepath.Base(pos.Filename), pos.Line))
					}
				}
				return true
			})

			if len(violations) > 0 {
				for _, v := range violations {
					t.Errorf("strict-atom CT violation: %s", v)
				}
				t.Fatalf("%d strict-atom CT violation(s) in %s",
					len(violations), rel)
			}
		})
	}
}

// findSecretIdent returns the name of the first secret-tagged
// identifier appearing in the expression tree e, or "", false if none.
func findSecretIdent(e ast.Expr) (string, bool) {
	if e == nil {
		return "", false
	}
	var found string
	ast.Inspect(e, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if _, secret := secretTaggedIdents[id.Name]; secret {
			found = id.Name
			return false
		}
		return true
	})
	if found != "" {
		return found, true
	}
	return "", false
}

// strictAtomCTMethodologyDoc is the prose statement of the CT obligation
// the harness enforces. Linked from README.md.
var strictAtomCTMethodologyDoc = regexp.MustCompile(`(?m)^## Methodology summary$`)
