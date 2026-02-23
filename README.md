# BIP-375 Test Vector Generator

Configuration-driven tool for generating test vectors for [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) (Silent Payments with PSBTs).

Reads YAML test configurations from `test_configs/` and produces `bip375_test_vectors.json` containing both valid and intentionally malformed PSBTs for use in implementation testing.

---

## Prerequisites

- Python ≥ 3.8
- Rust toolchain — required to compile `spdk_psbt` ([install via rustup](https://rustup.rs))
- `maturin` — Rust/Python build backend - automatically managed when using `pip install`

## Installing `spdk_psbt`

`spdk_psbt` is a Rust/uniffi Python extension. Its source lives in the `bip375-examples` repo under `rust/crates/spdk-uniffi`. Install it in editable mode, which compiles the Rust crate via maturin:

```bash
cd /path/to/bip375-examples/rust/crates/spdk-uniffi
pip install -e .
```

## Running the Generator

```bash
cd bip375-test-generator
pip install pyyaml
python test_generator.py
```

Output: `bip375_test_vectors.json`

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
    checks: [] # psbt_structure, ecdh_coverage, signer_constraints, output_scripts
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
|---|---|
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
