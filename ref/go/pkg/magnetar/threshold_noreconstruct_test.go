// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package magnetar

// threshold_noreconstruct_test.go --- proves the Track-B skeleton fails
// closed (no silent admission to POLARIS_MAX) and proves the structural
// no-reconstruct invariant: the SIGN/combiner path (OpenForsThreshold)
// never invokes a seed-reconstruction primitive, and the leaf-width
// guard refuses any interpolation wider than one one-time leaf.

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestNoReconstruct_FailClosed proves the Track-B signer + admission gate
// fail closed until NoReconstructProven().
func TestNoReconstruct_FailClosed(t *testing.T) {
	if NoReconstructProven() {
		t.Fatalf("NoReconstructProven() must be hard-wired false until the full construction is proven")
	}

	signer, err := NewFailClosedThresholdSigner(MustParamsFor(ModeM192s))
	if err != nil {
		t.Fatalf("NewFailClosedThresholdSigner: %v", err)
	}
	if _, err := signer.SignNoReconstruct([]byte("m"), []byte("ctx"), nil); !errors.Is(err, ErrNoReconstructUnproven) {
		t.Fatalf("SignNoReconstruct must fail closed with ErrNoReconstructUnproven, got %v", err)
	}

	// POLARIS_MAX admission gate refuses Track B.
	if err := AdmitMagnetarThresholdToPolarisMax(TrackBThreshold); !errors.Is(err, ErrNoReconstructUnproven) {
		t.Fatalf("Track B must be refused admission to POLARIS_MAX, got %v", err)
	}
	// Track A is not this gate's concern.
	if err := AdmitMagnetarThresholdToPolarisMax(TrackAQuorum); !errors.Is(err, ErrWrongTrackForGate) {
		t.Fatalf("Track A must return ErrWrongTrackForGate, got %v", err)
	}
	if err := AdmitMagnetarThresholdToPolarisMax(TrackUnspecified); !errors.Is(err, ErrUnknownTrack) {
		t.Fatalf("unspecified track must return ErrUnknownTrack, got %v", err)
	}
}

// TestNoReconstruct_LeafWidthGuard proves constraint 1's runtime guard:
// an interpolation at one-leaf width is permitted; anything approaching
// SeedSize is refused.
func TestNoReconstruct_LeafWidthGuard(t *testing.T) {
	params := MustParamsFor(ModeM192s)
	if params.N >= params.SeedSize {
		t.Fatalf("invariant broken: a leaf (n=%d) must be strictly narrower than the seed (%d)", params.N, params.SeedSize)
	}
	if err := assertLeafWidth(params, params.N); err != nil {
		t.Fatalf("one-leaf width must be permitted, got %v", err)
	}
	if err := assertLeafWidth(params, params.SeedSize); !errors.Is(err, ErrLeafWidthViolation) {
		t.Fatalf("seed-width interpolation must be refused, got %v", err)
	}
	if err := assertLeafWidth(params, params.N+1); !errors.Is(err, ErrLeafWidthViolation) {
		t.Fatalf("width > one leaf must be refused, got %v", err)
	}
	if err := assertLeafWidth(params, 0); !errors.Is(err, ErrLeafWidthViolation) {
		t.Fatalf("zero width must be refused, got %v", err)
	}
}

// forbiddenNoReconstructCalls are the seed-reconstruction / secret-side
// primitives that the no-reconstruct SIGN path must NEVER invoke. If
// OpenForsThreshold called any of these it would be reconstructing the
// global seed (KeyFromSeed / shakeIntoCat on the seed), running the
// secret-side signer (forsSign / slhSignAtom / assembleSignatureBytes),
// or dealing fresh shares (thbsseDealRandom*).
var forbiddenNoReconstructCalls = map[string]struct{}{
	"forsSign":               {},
	"slhSignAtom":            {},
	"assembleSignatureBytes": {},
	"KeyFromSeed":            {},
	"GenerateKey":            {},
	"shakeIntoCat":           {},
	"makePRFClosure":         {},
	"makePRFMsgClosure":      {},
	"thbsseDealRandom":       {},
	"thbsseDealRandomGF":     {},
	"deriveDKGPublicKey":     {},
}

// requiredNoReconstructCalls are the no-reconstruct primitives that
// OpenForsThreshold MUST invoke: the leaf-width Lagrange, the
// constraint-1 guard, and the constraint-3 burn.
var requiredNoReconstructCalls = map[string]struct{}{
	"thbsseReconstructGF": {}, // leaf-width interpolation only
	"assertLeafWidth":     {}, // constraint 1 guard
	"Burn":                {}, // constraint 3 burn
}

// collectCallNames returns the set of called function/method names within
// a function body (ast.Ident callees and ast.SelectorExpr selector names).
func collectCallNames(fn *ast.FuncDecl) map[string]struct{} {
	names := make(map[string]struct{})
	ast.Inspect(fn, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			names[f.Name] = struct{}{}
		case *ast.SelectorExpr:
			names[f.Sel.Name] = struct{}{}
		}
		return true
	})
	return names
}

// findFunc parses a source file in the current package directory and
// returns the named top-level function declaration.
func findFunc(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s not found in %s", name, file)
	return nil
}

// TestNoReconstruct_SourceGate_NoSeedReconstruction is the STRUCTURAL
// gate: it parses the no-reconstruct SIGN path (OpenForsThreshold) and
// asserts it never calls a seed-reconstruction / secret-side primitive,
// and DOES call the leaf-width interpolation + constraint guards.
//
// This is the structural counterpart of the runtime leaf-width guard:
// together they prove the SIGN path is incapable of forming the global
// seed. Contrast: assembleSignatureBytes (the existing reveal-and-
// aggregate Combine path) DOES call shakeIntoCat on a full SeedSize
// buffer --- this test asserts that contrast is real.
func TestNoReconstruct_SourceGate_NoSeedReconstruction(t *testing.T) {
	open := findFunc(t, "fors_threshold_open.go", "OpenForsThreshold")
	calls := collectCallNames(open)

	for forbidden := range forbiddenNoReconstructCalls {
		if _, found := calls[forbidden]; found {
			t.Fatalf("STRUCTURAL VIOLATION: OpenForsThreshold calls seed-reconstruction primitive %q --- "+
				"the no-reconstruct SIGN path must never invoke it", forbidden)
		}
	}
	for required := range requiredNoReconstructCalls {
		if _, found := calls[required]; !found {
			t.Fatalf("OpenForsThreshold must call no-reconstruct primitive %q (leaf-width Lagrange / constraint guards)", required)
		}
	}

	// Verify the contrast is real: the EXISTING reconstruct path
	// (assembleSignatureBytes) DOES expand a full buffer via shakeIntoCat.
	// If this ever stops being true the contrast claim is stale.
	assemble := findFunc(t, "thbsse_assemble.go", "assembleSignatureBytes")
	asmCalls := collectCallNames(assemble)
	if _, found := asmCalls["shakeIntoCat"]; !found {
		t.Fatalf("contrast stale: assembleSignatureBytes no longer expands a full buffer via shakeIntoCat")
	}
}

// TestBurnLedger_IdempotentAndConflict unit-tests the burn ledger.
func TestBurnLedger_IdempotentAndConflict(t *testing.T) {
	l := NewBurnLedger()
	addr := OneTimeAddr{Kind: KindWotsOneTime, Layer: 0, Tree: 1, Leaf: 2}
	var d1, d2 [32]byte
	d1[0], d2[0] = 1, 2

	if err := l.Burn(addr, d1); err != nil {
		t.Fatalf("first burn: %v", err)
	}
	if err := l.Burn(addr, d1); err != nil {
		t.Fatalf("idempotent re-burn under same digest must succeed: %v", err)
	}
	if !l.IsBurned(addr) {
		t.Fatalf("addr must be burned")
	}
	err := l.Burn(addr, d2)
	if !errors.Is(err, ErrOneTimeReuse) {
		t.Fatalf("re-burn under different digest must conflict, got %v", err)
	}
}
