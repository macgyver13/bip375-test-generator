# BIP-375 Test Vector Generator

Configuration-driven tool for generating test vectors for [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) (Silent Payments with PSBTs).

Reads YAML test configurations from `test_configs/` and produces `bip375_test_vectors.json` containing both valid and intentionally malformed PSBTs for use in implementation testing.

## Vector revisions

Significant changes to the vector files from the `v1.1.1` baseline. From the Workflows row on, `just gen-extended` also writes `out/bip375_test_vectors_extended.json`, which is not committed. Rows describe the committed standard file unless they say otherwise. The file version is the `version` string in that revision's JSON, and is shown only when it changes. A blank version cell belongs to the version above it. Milestone names the capability completed at that row, independent of the file version; a blank Milestone cell means no new milestone.

| File version | Milestone | Vector changes |
| --- | --- | --- |
| 1.1.1 | bips#2207 | Baseline. `k` assigned by BIP-375 canonical ordering and labeled spend keys. 19 valid, 22 invalid. |
| | | Negative-fee fix. PSBT map changed: valid “in progress: two P2TR inputs, neither is signed”. |
| | | Supplementary inputs standardized. Many valid and invalid PSBT maps are not equivalent to the previous row. |
| | | Signing replaced with the vendored Bitcoin Core `test_framework`. Many PSBT maps are not equivalent. |
| | | Missing `BIP32_DERIVATION` validation vector is no longer signed. One invalid PSBT map changed. |
| | bips#2253 | Added valid “input eligibility: bare OP_2 script is not a segwit v2 witness program”. 20 valid, 22 invalid. |
| 1.2.0 | Deterministic order | Fields serialized lexicographically. PSBT maps are equivalent; serialization order changed. |
| | bips#2286 | Added invalid “psbt structure: incorrect byte length for PSBT_OUT_SP_V0_LABEL field”. 20 valid, 23 invalid. |
| | bips#2310 | Added invalid “input eligibility: segwit version greater than 1 supplied via PSBT_IN_NON_WITNESS_UTXO with sp output”. 20 valid, 24 invalid. |
| | bips#2315 | Valid “input eligibility: bare OP_2 script is not a segwit v2 witness program” replaced by “in progress: two mixed input types - only eligible inputs contribute ECDH shares (bare OP_2 excluded, not a segwit v2 witness program)”. 20 valid, 24 invalid. |
| | | Change `scriptPubKey` matches `PSBT_OUT_BIP32_DERIVATION`. Three PSBT maps changed. |
| | | Signatures use the declared sighash type. The invalid non-`SIGHASH_ALL` and segwit version greater than 1 PSBT maps changed. |
| | | P2TR inputs derived from the tweaked output key. Four PSBT maps changed. |
| | | Signatures that cannot exist are dropped and a negative fee is fixed. Four invalid PSBT maps changed. |
| | | Valid vectors gained `supplementary.psbt_unique_id`, computed as BIP-375 specifies. PSBT maps are equivalent. |
| | | NUMS inputs are built from a script tree and carry `PSBT_IN_TAP_MERKLE_ROOT`. Two PSBT maps changed. |
| | SIGHASH_DEFAULT | Added valid “can finalize: one P2TR input signed with SIGHASH_DEFAULT”. 21 valid, 24 invalid. |
| | | Removed the per-vector `checks` field: every check applies to every vector. One invalid vector and the notes changed. |
| | | `--hex` adds `supplementary.hex`, the serialized PSBT, for diagnostics. Default output is unchanged. |
| | | Vectors gained a top-level `task`, the operation or expected failure for each vector. Invalid “psbt structure: PSBT_GLOBAL_TX_MODIFIABLE field is non-zero when PSBT_OUT_SCRIPT set for sp output” is renamed “input eligibility: PSBT_GLOBAL_TX_MODIFIABLE Inputs/Outputs Modifiable flags not cleared when PSBT_OUT_SCRIPT set for sp output”. PSBT maps are equivalent. |
| | Workflows | Added the generated `out/bip375_test_vectors_extended.json`: the standard vectors plus `workflows`, step vectors for a single-input global-share, a two-input global-share and a two-input per-input-share scenario, each step with `expected.psbt` and supplementary scoped to that step. `bip375_test_vectors.json` stays the standard set with no workflow steps. Both files report version 1.2.0. Standard: 21 valid, 24 invalid. Extended: 21 valid, 24 invalid, 17 workflow steps. |

---

## Prerequisites

- Python ≥ 3.8
- `pyyaml`

No Rust toolchain is needed. The generator defaults to a pure-Python PSBT
implementation, [py_spdk.py](py_spdk.py). The Rust `spdk_psbt` crate is not required:
it is only used to verify the Python implementation, or to generate with it directly
via `just backend=spdk <recipe>` (or `BIP375_PSBT_BACKEND=spdk`).

## Verifying against `spdk_psbt` (optional)

```bash
just test-parity
```

Generates the vectors and the rust-psbt `bip375.json` with both backends under
`out/parity/` and fails unless they produce identical files. This needs `spdk_psbt`
installed.

### Installing `spdk_psbt`

`spdk_psbt` is a Rust/UniFFI Python extension built from the
[bip375-examples](https://github.com/macgyver13/bip375-examples) repo, crate
`crates/spdk-uniffi`. The Python implementation is verified against version 1.2.5.
Building it needs a Rust toolchain ([install via rustup](https://rustup.rs)); `maturin`
is managed by `pip install`:

```bash
cd /path/to/bip375-examples/crates/spdk-uniffi
pip install -e .
```

Until the rust-psbt finalizer fix 1.2.5 depends on is published, bip375-examples builds
`psbt-v2` from a local rust-psbt checkout next to it (see the `[patch]` section in its
`Cargo.toml`).

## Running the Generator

```bash
cd bip375-test-generator
pip install pyyaml
python test_generator.py
```

Output:
- `bip375_test_vectors.json`: the standard vectors, what a validator for the merged
  BIP-375 text should accept and reject.
- `out/bip375_test_vectors_extended.json`: the standard vectors plus the optional sets
  named in its `includes` field. It is generated, not committed.

`--include` takes a comma-separated list of optional sets:
- `workflows`: the step-by-step workflow vectors.

`STANDARD_INCLUDES` in `test_generator.py` lists the sets every file includes, and
`VECTOR_VERSION` names the standard set. Both files report that version. To make workflow
vectors standard, add `"workflows"` to `STANDARD_INCLUDES` and bump `VECTOR_VERSION`.
`just test` regenerates the standard file, requires the committed copy to match, and
checks both files.

```bash
just gen           # bip375_test_vectors.json, the standard set
just gen-extended  # out/bip375_test_vectors_extended.json, with --include workflows
just gen-all       # both
```

Syncing: `just sync-bip` copies the standard file into bips, and `just sync-bip-extended`
copies the extended file under the standard name for a bips branch that runs workflows.
`sync-rust`, `sync-spdk` and `sync-jade` use the extended file. Each of these runs
`gen-extended` first.

Pass `--hex` to also write each serialized PSBT as `supplementary.hex`, for
diagnostics.

### rust-psbt Format Helper
```bash
just gen-rust
```

Writes `out/bip375.json` from the extended file. Generated artifacts other than
`bip375_test_vectors.json` live in the untracked `out/` directory and can be
regenerated at any revision.

### Regenerating vectors across a jj stack

```bash
just regen-stack '@::<revision tip>'
```

Edits each mutable revision from `@` through `<revision tip>`, oldest first, and regenerates
`bip375_test_vectors.json` with the configured backend (`py` unless `BIP375_PSBT_BACKEND` or
`just backend=spdk` says otherwise). This replaces conflicted copies of the file left by a
rebase. If the generator fails, it stops and leaves `@` at the failing revision; otherwise it
returns to the starting revision.

### Vendored Bitcoin Core test_framework

Bitcoin transaction, script, sighash, signing, and secp256k1 primitives are
provided by a vendored snapshot of Bitcoin Core's `test/functional/test_framework`
in `test_framework/` (origin commit `d7ed2840ac`). `util.py` is trimmed to the
helpers the vendored modules actually use. Only the BIP-375 silent-payment
specifics remain custom in `generator_utils.py`.

### Output sections

The extended file has three vector arrays; the standard file has `valid` and `invalid`.

- `valid` / `invalid` — one-shot config-driven PSBTs (see YAML config below).
- `workflows` — a single PSBT walked **step by step** through the BIP-375 roles.
  Generated by `WorkflowVectorGenerator` using the PSBT backend's high-level role methods.

BIP-375 gives the **Signer** the ECDH shares, the DLEQ proofs and the silent payment
output scripts. It may only set `PSBT_OUT_SCRIPT` once every eligible input carries a
share, and it must not sign before those scripts are set. So the number of Signer steps
depends on how the shares are contributed.

A global ECDH share means one party owns every input, and it acts once:

```text
creator → updater → signer → finalizer → extractor
```

With per-input shares and `n` signers, no party can compute the output scripts until the
last share lands. The `n`-th signer therefore computes the scripts, clears the modifiable
flags and signs its own input; the others return in a second round to sign:

```text
creator → updater
        → signer × (n-1)   share + DLEQ proof, cannot yet sign
        → signer           final share → output scripts, flags cleared, signs its input
        → signer × (n-1)   scripts are set, signs its input
        → finalizer → extractor
```

Each workflow entry is an **atomic step vector**:

```jsonc
{
  "psbt": "<base64>",        // the PSBT this role received
  "description": "Two-input workflow: Updater adds UTXO and BIP32 derivation data",
  "task": "updater",         // BIP-375 role that acted, in workflows[]
  "supplementary": {
    "inputs": [...], "outputs": [...]
  },
  "expected": { "psbt": "<base64>" }   // plus "tx": "<hex>" on the extractor step
}
```

`task` names the BIP-375 role that acted. The same `task` key is reused by the
`valid`/`invalid` vectors, where it instead records an expected outcome (`sign`, `fail_sign`,
…) rather than a role.

`supplementary` otherwise uses the same field shapes as the `valid`/`invalid` vectors, but
is **scoped to the material that has become meaningful at that step** — `sp_proofs` list
only the shares already present in `expected.psbt`, output `script` appears only once the
Signer has computed it, and `private_key` is shown only for the party acting in that step.
It is diagnostic only. `expected.psbt` is the base64 PSBT after that role runs.

---

## YAML Test Configuration

Test scenarios are defined in YAML files under two directories:

- `test_configs/valid/` — scenarios expected to produce well-formed PSBTs (6 files)
- `test_configs/invalid/` — scenarios designed to exercise validation failures (5 files)

Each file maps to a logical test category (e.g. ECDH coverage, PSBT structure errors, signer constraints).

### Top-level structure

```yaml
description: "Human-readable description of this config file"

test_cases:
  - description: "Specific scenario"
    task: "sign"                 # operation or expected failure mode for the case
    validation_result: "valid"   # or "invalid"
    inputs: [...]
    outputs: [...]
    scan_keys: [...]
    control_override: {...}      # optional — injects faults for invalid cases
```

### `inputs`

Each entry defines a UTXO contributing to the PSBT:

```yaml
inputs:
  - type: "p2wpkh"               # p2wpkh | p2sh_multisig | p2wsh_multisig | p2tr
    amount: 100000               # satoshis
    key_derivation_suffix: "id"  # string seed for deterministic key generation
    count: 2                     # optional: repeat N identical inputs
    sequence: 0xFFFFFFFE         # optional
    multisig_threshold: 2        # required for multisig types
    multisig_pubkey_count: 3     # required for multisig types
```

### `outputs`

Each entry defines a PSBT output:

```yaml
outputs:
  - type: "silent_payment"       # silent_payment | regular_p2wpkh | regular_p2tr
    amount: 95000
    scan_key_id: "default"       # references a key_id in scan_keys (silent_payment only)
    spend_key_id: "optional_id"  # optional override
    label: 1                     # optional BIP-352 label integer
    add_bip32_derivation: true   # for regular outputs
```

### `scan_keys`

Defines the scan/spend key pairs referenced by silent payment outputs:

```yaml
scan_keys:
  - key_id: "default"
    derivation_suffix: "recipient"   # optional deterministic seed
  - key_id: "second_recipient"
    derivation_suffix: "other"
```

### `control_override`

Optional section for injecting intentional faults into invalid test cases. Common fields:

| Field | Effect |
| --- | --- |
| `missing_ecdh_for_input: N` | Omit ECDH share for input at index N |
| `missing_ecdh_for_scan_key: "key_id"` | Omit ECDH share for a specific scan key |
| `wrong_ecdh_share_size: true` | Malform the PSBT_IN_SP_ECDH_SHARE field size |
| `missing_dleq_for_input: N` | Omit DLEQ proof for input N |
| `invalid_dleq_for_input: N` | Corrupt the DLEQ proof for input N |
| `missing_dleq_for_scan_key: "key_id"` | Omit DLEQ proof for a specific scan key |
| `invalid_dleq_for_scan_key: "key_id"` | Corrupt DLEQ proof for a specific scan key |
| `wrong_dleq_proof_size: true` | Malform the PSBT_IN_SP_DLEQ field size |
| `missing_global_dleq: true` | Omit the global DLEQ proof |
| `invalid_global_dleq: true` | Corrupt the global DLEQ proof |
| `wrong_sp_info_size: true` | Malform the PSBT_OUT_SP_V0_INFO field size |
| `missing_sp_info_field: true` | Omit PSBT_OUT_SP_V0_INFO from a labeled output |
| `wrong_sighash_for_input: N` | Set invalid sighash type for input N |
| `use_global_ecdh: ["key_id"]` | Use global ECDH share for listed scan key IDs |
| `use_segwit_v2_input: true` | Include a segwit v2 (ineligible) input |
| `set_tx_modifiable: true` | Set the PSBT_GLOBAL_TX_MODIFIABLE flag |
| `force_output_script: true` | Inject wrong output script |
| `inject_ineligible_ecdh: true` | Add ECDH data to non-eligible inputs |
| `strip_input_pubkeys_for_input: N` | Remove public keys from input N |

## Diagnostics

### Explain PSBT changes between revisions

Raw diffs of base64 PSBTs are not meaningful because one early byte changes the
rest of the encoded line. Compare decoded PSBT maps instead:

```sh
just diff-vectors                 # @- versus @
just diff-vectors main @          # any two jj revisions
just diff-vectors @- @ -v         # affected field type codes
just diff-vectors @- @ -vv        # values and complete serialization ordering
python psbt_diff.py --jj @- @ -vv -f 'missing ECDH share'
```

Without verbosity the report only lists PSBTs whose maps are not equivalent. `-v`
adds changed field type codes and compact ordering information. `-vv` adds decoded
values and complete old/new serialization sequences, including key data. The report
matches vectors by section and description. Individual PSBT strings or saved JSON
files can also be compared directly:

```sh
python psbt_diff.py 'OLD_BASE64' 'NEW_BASE64'
python psbt_diff.py old.json new.json
```

### Display supplementary data

```sh
jq -r '(.valid[], .invalid[]) | select(.supplementary.inputs != null) | .description, .task, (.supplementary.inputs[] | "  input \(.input_index): signed=\(.signed)")' bip375_test_vectors.json
```
