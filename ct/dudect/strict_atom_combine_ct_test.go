// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build ct
// +build ct

// Package dudect carries a Magnetar source-hygiene LINT. Run via:
//
//	go test -tags ct -run TestStrictAtom_IdentHygiene ./ct/dudect/...
//
// or via scripts/checks/dudect-smoke.sh.
//
// =====================================================================
//
//	THIS IS NOT A CONSTANT-TIME TEST. IT IS A NAME LINT.
//
// =====================================================================
//
// The check below parses the Combine emit-path sources and asserts
// that no identifier whose NAME is in a hardcoded list feeds an `if`,
// a `switch`, or an index expression. That is a property of variable
// NAMES, not of timing or memory-access behavior:
//
//   - It does NOT measure execution time (no dudect, no statistical
//     test, no cycle counting).
//   - It does NOT track data flow: a secret that flows into a branch
//     under a name NOT in the list is invisible to it.
//   - It does NOT establish constant-timeness of any function.
//
// More fundamentally, constant-time is the WRONG property to assert
// for this path at all: `assembleSignatureBytes` reconstructs the
// full FIPS 205 master into `derivedMaterial`. A timing side-channel
// is moot when the secret is already sitting in plaintext in the
// combiner's buffer (see BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11 and
// ASSEMBLE-INVARIANT.md). Treat this file as an identifier-style lint
// that keeps the named scratch buffers out of obvious branch/index
// positions, and nothing more.
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

// secretTaggedIdent patterns. This is a NAME list, not a taint
// analysis. The lint flags an identifier ONLY when its spelling
// appears in this set AND it sits in a branch/index position. A
// secret carried under any other name is not detected. This catches
// nothing about timing; it is a style guard that keeps these
// specific scratch-buffer names out of obvious control-flow / index
// positions.
var secretTaggedIdents = map[string]struct{}{
	"derivedMaterial":      {},
	"derivedExpandInput":   {},
	"derivedPkSeedSegment": {},
	"secretSegment":        {},
	"prfAbsorb":            {},
	"prfMsgAbsorb":         {},
}

// TestStrictAtom_IdentHygiene_NoNamedBufferInBranch is an
// identifier-hygiene LINT (NOT a constant-time property, NOT a
// security gate). It parses the Combine emit-path sources, walks the
// AST, and asserts no identifier whose NAME is in secretTaggedIdents
// feeds a control-flow branch or an index expression. See the package
// banner: this measures nothing about timing and proves nothing about
// confidentiality.
func TestStrictAtom_IdentHygiene_NoNamedBufferInBranch(t *testing.T) {
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
					t.Errorf("strict-atom ident-hygiene lint: %s", v)
				}
				t.Fatalf("%d strict-atom ident-hygiene lint hit(s) in %s",
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
