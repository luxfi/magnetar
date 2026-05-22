// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

// dkg2_test.go — Skeleton-tier tests. These do NOT exercise the
// (open-research) MPC-root layer; they pin the wire-shape contract
// and the ErrSkeletonOnly / ErrMPCRootNotImpl sentinels so a
// production caller cannot consume the unfinished pipeline by
// accident.

import (
	"errors"
	"testing"
)

func testCommittee(n int) []Participant {
	out := make([]Participant, n)
	for i := 0; i < n; i++ {
		var id PartyID
		id[0] = byte(i + 1)
		copy(id[1:], []byte("DKG2-TEST"))
		out[i] = Participant{ID: id, EvalPoint: uint16(i + 1)}
	}
	return out
}

func testConfig() Config {
	parts := testCommittee(3)
	return Config{
		ChainID:      []byte("lux-magnetar-dkg2-test"),
		Epoch:        1,
		Threshold:    2,
		Participants: parts,
		Elements: []ElementID{
			{Type: 1, Slot: 0, ChainIdx: 0},
			{Type: 1, Slot: 0, ChainIdx: 1},
			{Type: 2, Slot: 0, TreeIdx: 0, LeafIdx: 0},
		},
	}
}

// TestDeal_SkeletonOnly pins the Deal-returns-ErrSkeletonOnly
// contract. A production caller invoking Deal must hit the
// sentinel; if a future commit removes the sentinel WITHOUT
// implementing the MPC layer, this test catches it.
func TestDeal_SkeletonOnly(t *testing.T) {
	cfg := testConfig()
	_, err := Deal(cfg, cfg.Participants[0].ID)
	if !errors.Is(err, ErrSkeletonOnly) {
		t.Fatalf("Deal err = %v, want ErrSkeletonOnly", err)
	}
}

// TestVerify_SkeletonOnly pins the Verify-returns-ErrSkeletonOnly
// contract on a non-nil bundle.
func TestVerify_SkeletonOnly(t *testing.T) {
	cfg := testConfig()
	bundle := &DealtBundle{}
	err := Verify(cfg, cfg.Participants[0].ID, bundle)
	if !errors.Is(err, ErrSkeletonOnly) {
		t.Fatalf("Verify err = %v, want ErrSkeletonOnly", err)
	}
}

// TestFileComplaint_SkeletonOnly pins the complaint-round stub.
func TestFileComplaint_SkeletonOnly(t *testing.T) {
	cfg := testConfig()
	_, err := FileComplaint(cfg, cfg.Participants[0].ID, nil)
	if !errors.Is(err, ErrSkeletonOnly) {
		t.Fatalf("FileComplaint err = %v, want ErrSkeletonOnly", err)
	}
}

// TestDealerDefend_SkeletonOnly pins the defense stub.
func TestDealerDefend_SkeletonOnly(t *testing.T) {
	cfg := testConfig()
	_, err := DealerDefend(cfg, cfg.Participants[0].ID, nil)
	if !errors.Is(err, ErrSkeletonOnly) {
		t.Fatalf("DealerDefend err = %v, want ErrSkeletonOnly", err)
	}
}

// TestProposeQ_SkeletonOnly pins the agreement-proposal stub.
func TestProposeQ_SkeletonOnly(t *testing.T) {
	cfg := testConfig()
	_, err := ProposeQ(cfg, cfg.Participants[0].ID, nil, nil)
	if !errors.Is(err, ErrSkeletonOnly) {
		t.Fatalf("ProposeQ err = %v, want ErrSkeletonOnly", err)
	}
}

// TestAgreeQ_SkeletonOnly pins the agreement stub.
func TestAgreeQ_SkeletonOnly(t *testing.T) {
	cfg := testConfig()
	_, err := AgreeQ(cfg, nil)
	if !errors.Is(err, ErrSkeletonOnly) {
		t.Fatalf("AgreeQ err = %v, want ErrSkeletonOnly", err)
	}
}

// TestRun_SkeletonOnly pins the top-level orchestrator stub.
func TestRun_SkeletonOnly(t *testing.T) {
	cfg := testConfig()
	err := Run(cfg)
	if !errors.Is(err, ErrSkeletonOnly) {
		t.Fatalf("Run err = %v, want ErrSkeletonOnly", err)
	}
}

// TestRootMPC_MPCRootNotImpl pins the MPC-root unfinished marker.
// This is the SPECIFIC sentinel pointing at the open research task.
// A production caller CANNOT consume RootMPC; the error explicitly
// names the BLOCKERS.md entry.
func TestRootMPC_MPCRootNotImpl(t *testing.T) {
	cfg := testConfig()
	err := RootMPC(cfg, nil)
	if !errors.Is(err, ErrMPCRootNotImpl) {
		t.Fatalf("RootMPC err = %v, want ErrMPCRootNotImpl", err)
	}
}

// TestValidateConfig_BadThreshold pins the structural validation.
func TestValidateConfig_BadThreshold(t *testing.T) {
	cfg := testConfig()
	cfg.Threshold = 0
	if err := validateConfig(cfg); !errors.Is(err, ErrInvalidPVSSConfig) {
		t.Fatalf("validateConfig threshold=0 err = %v, want ErrInvalidPVSSConfig", err)
	}
	cfg = testConfig()
	cfg.Threshold = uint16(len(cfg.Participants) + 1)
	if err := validateConfig(cfg); !errors.Is(err, ErrInvalidPVSSConfig) {
		t.Fatalf("validateConfig threshold>n err = %v, want ErrInvalidPVSSConfig", err)
	}
}

// TestValidateConfig_EmptyElements pins that a DKG over an empty
// element set is rejected (catches caller bugs).
func TestValidateConfig_EmptyElements(t *testing.T) {
	cfg := testConfig()
	cfg.Elements = nil
	if err := validateConfig(cfg); !errors.Is(err, ErrInvalidPVSSConfig) {
		t.Fatalf("validateConfig empty-elements err = %v, want ErrInvalidPVSSConfig", err)
	}
}

// TestValidateConfig_ZeroEvalPoint pins that EvalPoint=0 (the
// Shamir master-secret point) is rejected.
func TestValidateConfig_ZeroEvalPoint(t *testing.T) {
	cfg := testConfig()
	cfg.Participants[1].EvalPoint = 0
	if err := validateConfig(cfg); !errors.Is(err, ErrInvalidPVSSConfig) {
		t.Fatalf("validateConfig zero-EvalPoint err = %v, want ErrInvalidPVSSConfig", err)
	}
}

// TestValidateConfig_DuplicateEvalPoint pins distinct-EvalPoint
// enforcement.
func TestValidateConfig_DuplicateEvalPoint(t *testing.T) {
	cfg := testConfig()
	cfg.Participants[1].EvalPoint = cfg.Participants[0].EvalPoint
	if err := validateConfig(cfg); !errors.Is(err, ErrInvalidPVSSConfig) {
		t.Fatalf("validateConfig dup-EvalPoint err = %v, want ErrInvalidPVSSConfig", err)
	}
}

// TestQualifiedSet_SetHas pins the bitmap behaviour.
func TestQualifiedSet_SetHas(t *testing.T) {
	q := NewQualifiedSet(8)
	if q.Has(0) {
		t.Fatalf("fresh QualifiedSet should have no bits set")
	}
	q.Set(3)
	q.Set(7)
	if !q.Has(3) || !q.Has(7) {
		t.Fatalf("Set bits not retrievable via Has")
	}
	if q.Has(2) || q.Has(4) {
		t.Fatalf("Unset bits returned true from Has")
	}
}

// TestComplaintKind_String pins the wire-stable string mapping.
func TestComplaintKind_String(t *testing.T) {
	cases := []struct {
		k    ComplaintKind
		want string
	}{
		{ComplaintBadShare, "bad-share"},
		{ComplaintMissingDelivery, "missing-delivery"},
		{ComplaintCommitmentMalformed, "commitment-malformed"},
		{ComplaintKind(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("ComplaintKind(%d).String() = %q, want %q", c.k, got, c.want)
		}
	}
}
