# Magnetar --- GPU acceleration port plan

This document scopes the v1.3 GPU-acceleration work item:
landing four batched FIPS 205 SLH-DSA hash-tree kernels at
`lux-private/gpu-kernels/ops/crypto/slhdsa/` and wiring them
through `luxcpp/gpu` into the magnetar `slhSignAtom` substrate.

> **Why this isn't already done.** The shipped magnetar
> implementation (`ref/go/pkg/magnetar/slhdsa_internal.go`) walks
> FIPS 205 §5-§8 sequentially in pure Go. For consensus-rate
> signing (1 sig/block) this is sufficient on commodity CPU. The
> GPU path is for throughput consumers: bridge custody, N=100+
> aggregate-cert verification, slashing-evidence sweep across
> historical blocks.

---

## 1. The substrate that already exists

`lux-private/gpu-kernels/ops/crypto/` already ships:

| Op | Backends | Purpose for Magnetar |
|---|---|---|
| `shake256/` | CUDA + HIP + Metal + Vulkan + WGSL | FIPS 202 XOF; every SLH-DSA hash call goes through here |
| `sha3_256/` | CUDA + HIP + Metal + Vulkan + WGSL | Same Keccak-f[1600] permutation, different domain separator |
| `keccak256/` | CUDA + HIP + Metal + Vulkan + WGSL | Same permutation, Ethereum padding |

Permission to share `keccak_f1600.cuh` is documented in the
`shake256/op.yaml` notes block:

> Shares the same Keccak-f[1600] permutation as keccak256 /
> sha3_256 / cshake256. The CUDA / HIP TUs pull in
> `../keccak256/keccak_f1600.cuh` for one source of truth on the
> permutation; Vulkan + WGSL embed identical f1600 bodies in
> their respective shaders (GLSL/WGSL have no shared-include
> mechanism that survives the per-backend shader staging step).

The four magnetar kernels below sit on top of `shake256` and add
NO new permutation code --- they are FIPS 205-shape composition
of existing SHAKE256 absorbs.

---

## 2. Kernel 1: `magnetar_wotsplus_chain_batch`

### Signature

```
status = lux_gpu_magnetar_wotsplus_chain_batch(
    const lux_magnetar_wots_chain_input* in,   // batch of input tuples
    lux_magnetar_wots_chain_output* out,        // batch of output bytes
    size_t batch_size                            // M (>= 1)
);

struct lux_magnetar_wots_chain_input {
    const uint8_t* pk_seed;       // n bytes (n = 24 for M192s, 32 for M256s)
    uint8_t        addr[32];      // FIPS 205 §4.2 address (32 bytes for SHAKE)
    const uint8_t* x_base;        // n bytes (the chain base)
    uint32_t       i;             // starting hash address
    uint32_t       s;             // chain length (0..15 for w=16)
};

struct lux_magnetar_wots_chain_output {
    uint8_t out[32];   // n bytes (24 for M192s, 32 for M256s); upper bytes zero
};
```

### Semantics

For each batch element `(pk_seed, addr, x_base, i, s)`:

```
tmp ← x_base
for j ∈ [i, i+s):
    addr.setHashAddress(j)        // mutate bytes [28:32] of addr
    tmp ← SHAKE256(pk_seed || addr || tmp)[:n]
out ← tmp
```

This is FIPS 205 §5 Algorithm 5 `chain`, executed independently
for each batch element.

### Parallelism

- **Across batch elements**: trivial, one CUDA thread / Metal
  thread / Vulkan workgroup per element.
- **Within one element**: NONE (chain is sequential by
  construction).

### Use sites in `ref/go/pkg/magnetar/slhdsa_internal.go`

- `wotsChain` line 402 — invoked inside `wotsSign:442` and
  `wotsPkFromSig:645`.
- `wotsSign` line 442 — `wotsLen = 2n + 3` chain computations per
  WOTS+ signature.
- `wotsPkGen` line 499 — same.
- `wotsPkFromSig` line 645 — used in `xmssPkFromSig:607`,
  which is invoked `d-1` times during hypertree sign (verify-side
  recomputation for the chained-root case).

### Volume per signature (M192s shape: n=24, d=7, hPrime=9, wotsLen=51)

- One hypertree sign: `d × 2^hPrime × wotsLen` chain computations
  for full PK gen at one layer (only at layer 0, the leaves):
  `1 × 512 × 51 = 26,112` chains.
- WOTS+ sign per leaf: `wotsLen = 51` chains.
- Total per signature: ~26,000-30,000 chains. At GPU throughput of
  ~10⁷ chains/sec on H100 → ~3ms per signature for the
  WOTS+ kernel alone.

---

## 3. Kernel 2: `magnetar_fors_subtree_batch`

### Signature

```
status = lux_gpu_magnetar_fors_subtree_batch(
    const lux_magnetar_fors_subtree_input* in,
    lux_magnetar_fors_subtree_output* out,
    size_t batch_size
);

struct lux_magnetar_fors_subtree_input {
    const uint8_t* pk_seed;        // n bytes
    uint8_t        addr[32];       // FIPS 205 §4.2 address
    uint32_t       leaf_idx;       // FORS subtree leaf index
    uint32_t       height;         // FORS subtree height to compute
    // The secret-derived FORS seed is provided host-side via
    // the prfOut callback; per-element callers pre-populate the
    // sk_leaves array with the PRF outputs for the relevant
    // leaves.
    const uint8_t* sk_leaves;      // (2^height) × n bytes
};

struct lux_magnetar_fors_subtree_output {
    uint8_t out[32];   // n bytes (the subtree node value)
};
```

### Semantics

For each batch element, compute the FORS subtree node at
`(leaf_idx, height)` using `F(pk_seed, addr, sk_leaf_i)` at the
leaves and `H(pk_seed, addr, left || right)` at internal nodes.
FIPS 205 §8.2 Algorithm 15.

### Parallelism

- **Across batch elements**: one thread block per element.
- **Within one element**: across the `2^height` leaves and the
  pairwise reductions at each height level (binary-tree
  reduction).

### Use sites

- `forsNodeCompute` line 735.
- `forsSign` line 780 — `k` subtrees per signature; for M192s,
  `k=17` subtrees of height `a=14`.

### Volume per signature (M192s shape)

- `k × (2^a - 1) = 17 × 16383 = ~280K` SHAKE absorbs.
- Plus the secret-derived `sk_leaf` computations: `k × 2^a =
  ~278K` PRF callbacks (handled on the host inside the
  strict-atom callback).

---

## 4. Kernel 3: `magnetar_xmss_subtree_batch`

### Signature

```
status = lux_gpu_magnetar_xmss_subtree_batch(
    const lux_magnetar_xmss_subtree_input* in,
    lux_magnetar_xmss_subtree_output* out,
    size_t batch_size
);

struct lux_magnetar_xmss_subtree_input {
    const uint8_t* pk_seed;        // n bytes
    uint8_t        addr[32];
    uint32_t       leaf_idx;
    uint32_t       height;
    // Host pre-populates the WOTS+ public-key values at the
    // leaves of this subtree.
    const uint8_t* wots_pk_leaves; // (2^height) × n bytes
};

struct lux_magnetar_xmss_subtree_output {
    uint8_t out[32];   // n bytes (the subtree node value)
};
```

### Semantics

For each batch element, compute the XMSS subtree node at
`(leaf_idx, height)` using `H(pk_seed, addr, left || right)`
internal nodes. FIPS 205 §6.1 Algorithm 9.

The WOTS+ leaf computation is delegated to kernel 1; this kernel
takes the resulting leaf bytes as input and performs the
pairwise hash reductions.

### Parallelism

- **Across batch elements**: one thread block per element.
- **Within one element**: binary-tree reduction.

### Use sites

- `xmssNodeCompute` line 546.
- `xmssSign` line 582 — auth-path computation (`hPrime` sibling
  nodes per XMSS layer).
- `xmssPkFromSig` line 607 — verifier-side recomputation.

### Volume per signature (M192s shape: hPrime=9, d=7)

- Per XMSS sign: `hPrime` auth-path nodes; each requires a
  subtree node at some height. Total: ~256 SHAKE absorbs per
  XMSS sign.
- Per hypertree sign: `d × xmss_sign_cost` = `7 × ~256 = ~1,800`
  SHAKE absorbs.

---

## 5. Kernel 4: `magnetar_hmsg_prfmsg_batch`

### Signature

```
status = lux_gpu_magnetar_hmsg_prfmsg_batch(
    const lux_magnetar_hmsg_input*   hmsg_in,    // batch of H_msg inputs
    lux_magnetar_hmsg_output*        hmsg_out,
    const lux_magnetar_prfmsg_input* prfmsg_in,  // batch of PRF_msg inputs
    lux_magnetar_prfmsg_output*      prfmsg_out,
    size_t hmsg_batch,
    size_t prfmsg_batch
);

struct lux_magnetar_hmsg_input {
    const uint8_t* r;        // n bytes
    const uint8_t* pk_seed;  // n bytes
    const uint8_t* pk_root;  // n bytes
    const uint8_t* msg_prime;
    size_t         msg_prime_len;
};

struct lux_magnetar_hmsg_output {
    uint8_t digest[64];   // m bytes (39 for M192s, 42 for M192f, 47 for M256s)
};

struct lux_magnetar_prfmsg_input {
    const uint8_t* sk_prf_segment;  // n bytes; provided by host via strict-atom callback
    const uint8_t* opt_rand;         // n bytes
    const uint8_t* msg_prime;
    size_t         msg_prime_len;
};

struct lux_magnetar_prfmsg_output {
    uint8_t out[32];    // n bytes
};
```

### Semantics

`H_msg(R, PK.seed, PK.root, M')` and `PRF_msg(SK.prf, optRand,
M')` per FIPS 205 §11.2 SHAKE instantiation. Both are single
SHAKE256 absorb-and-squeeze calls.

### Parallelism

Trivial across batch elements.

### Use sites

- `hMsgPub` line 341 — exactly one per signature.
- `prfMsg` callback — exactly one per signature.

### Volume per signature

2 SHAKE absorbs (one per kernel). These exist as a separate
kernel only because batching them across many independent
signatures amortizes the kernel launch overhead.

---

## 6. File layout

```
lux-private/gpu-kernels/
└── ops/
    └── crypto/
        └── slhdsa/                      # NEW
            ├── op.yaml                  # op metadata; 5 backends
            ├── cuda.cu                  # 4 kernels in one TU
            ├── hip.cu                   # mirror, __HIPCC__-gated
            ├── metal.metal              # MSL source
            ├── vulkan/                  # GLSL sources
            │   ├── wotsplus_chain.comp
            │   ├── fors_subtree.comp
            │   ├── xmss_subtree.comp
            │   └── hmsg_prfmsg.comp
            └── wgsl/                    # WGSL sources
                ├── wotsplus_chain.wgsl
                ├── fors_subtree.wgsl
                ├── xmss_subtree.wgsl
                └── hmsg_prfmsg.wgsl
```

Plus the C ABI extension at
`luxcpp/gpu/include/lux/gpu.h`:

```
// SLH-DSA hash-tree batched primitives. See ops/crypto/slhdsa/op.yaml.
int lux_gpu_magnetar_wotsplus_chain_batch(
    const lux_magnetar_wots_chain_input*  in,
    lux_magnetar_wots_chain_output*       out,
    size_t                                 batch_size);

int lux_gpu_magnetar_fors_subtree_batch(/* ... */);
int lux_gpu_magnetar_xmss_subtree_batch(/* ... */);
int lux_gpu_magnetar_hmsg_prfmsg_batch(/* ... */);
```

Plus the backend plugin ABI extension at
`luxcpp/gpu/include/lux/gpu/backend_plugin.h` (v9 bump):

```
typedef int (*op_magnetar_wotsplus_chain_batch_fn)(/* same shape */);
// Three more.
```

CPU backend reference implementation at
`luxcpp/gpu/src/cpu_backend.cpp::cpu_op_magnetar_wotsplus_chain_batch`
mirrors `wotsChain` in `slhdsa_internal.go` --- per-element
sequential, no parallelism inside the chain --- so CPU oracle is
the reference for byte-identity tests.

---

## 7. Go-side wiring

The pluggability seam in magnetar is the existing `prfOut`
callback (`slhdsa_internal.go:286`). For the GPU acceleration
path we add ONE additional seam: a `publicHashBatch` interface
that the four hash-tree primitives dispatch to when available.

```go
// PublicHashBatch is the optional batched-SHAKE substrate.
// Implementations include luxcpp/gpu via cgo bindings.
// The strict-atom Combine path holds a PublicHashBatch reference
// and dispatches to it for the four kernels above when the
// batch size exceeds the dispatch threshold.
type PublicHashBatch interface {
    WotsPlusChainBatch(in []WotsChainInput, out []WotsChainOutput) error
    ForsSubtreeBatch(in []ForsSubtreeInput, out []ForsSubtreeOutput) error
    XmssSubtreeBatch(in []XmssSubtreeInput, out []XmssSubtreeOutput) error
    HMsgPrfMsgBatch(hmsgIn []HMsgInput, hmsgOut []HMsgOutput,
                    prfMsgIn []PrfMsgInput, prfMsgOut []PrfMsgOutput) error
}
```

Wiring at `assembleSignatureBytes` and `ValidatorBatchVerify` is
the same shape `luxfi/crypto/slhdsa/gpu.go` already uses for the
existing `luxfi/accel`-based path: detect the substrate via
`accel.Available()`, route batches above the threshold to GPU,
fall back to CPU for small batches.

---

## 8. Expected throughput

Conservative estimates (numbers grounded in the existing
`luxfi/crypto/slhdsa` GPU benches and the published `shake256`
kernel performance on Apple M1 Max + NVIDIA H100):

| Op | CPU 1-core (M1 Max) | GPU M1 Max Metal (batch 64) | GPU H100 (batch 256) |
|---|---|---|---|
| SLH-DSA-SHAKE-192s sign | ~80 ms | ~5 ms (16x) | ~0.6 ms (130x) |
| SLH-DSA-SHAKE-192s verify | ~2 ms | ~0.15 ms (13x) | ~0.05 ms (40x) |

### Threshold for GPU dispatch

Matches the existing
`crypto/slhdsa.LastValidatorBatchTier` pattern:

| Tier | Batch size | Backend |
|---|---|---|
| Serial | 1..63 | CPU single-core |
| Concurrent | 64..511 | CPU goroutine-parallel |
| GPU | 512+ | luxcpp/gpu (if Available) |

The break-even at 512 reflects the kernel-launch overhead on
discrete GPUs; on Apple Silicon UMA the break-even is lower
(~64 elements).

---

## 9. Verification + tests

Each kernel is byte-identity tested against the CPU oracle (which
is the existing `slhdsa_internal.go` walk):

```
ops/crypto/slhdsa/tests/
├── test_magnetar_wotsplus_chain_kat.cpp     # NIST FIPS 205 KAT
├── test_magnetar_fors_subtree_kat.cpp
├── test_magnetar_xmss_subtree_kat.cpp
└── test_magnetar_hmsg_prfmsg_kat.cpp
```

Each test:
1. Runs the CPU oracle on a fixed input batch.
2. Runs the active GPU plugin on the same batch.
3. Byte-compares outputs.

The vector source is FIPS 205 Algorithm 22 (slh_sign) intermediate
states, captured from `cloudflare/circl/sign/slhdsa` at the four
seams. Vectors live at
`lux-private/gpu-kernels/ops/crypto/slhdsa/vectors/`.

---

## 10. v1.3 work-item summary

| Task | Estimate | Owner |
|---|---|---|
| Land 4 CUDA kernels + tests | 5 days | tbd |
| Land 4 HIP kernels (port from CUDA via macro gating) | 1 day | tbd |
| Land 4 Metal kernels + KAT | 4 days | tbd |
| Land 4 Vulkan GLSL kernels + KAT | 4 days | tbd |
| Land 4 WGSL kernels + KAT | 3 days | tbd |
| `luxcpp/gpu` C ABI + plugin ABI extension (v8 → v9) | 2 days | tbd |
| CPU oracle in `luxcpp/gpu/src/cpu_backend.cpp` | 2 days | tbd |
| Magnetar Go-side `PublicHashBatch` interface + wiring | 3 days | tbd |
| `luxfi/crypto/slhdsa/gpu.go` dispatch update | 1 day | tbd |
| Bench suite + leaderboard cells | 2 days | tbd |
| **Total** | **~27 days** | |

Status: PROPOSED. Not v1.2-blocking.

---

**Document metadata**

- Name: `GPU-PORT-PLAN.md`
- Date: 2026-06-03
- Tracks: `BLOCKERS.md::MAGNETAR-GPU-PORT-V13`
