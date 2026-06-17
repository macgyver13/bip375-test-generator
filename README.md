# BIP-375 Test Vector Generator

Configuration-driven tool for generating test vectors for [BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) (Silent Payments with PSBTs).

Reads YAML test configurations from `test_configs/` and produces `bip375_test_vectors.json` containing both valid and intentionally malformed PSBTs for use in implementation testing.

---

## Prerequisites

- Python ≥ 3.8
- Rust toolchain — required to compile `spdk_psbt` ([install via rustup](https://rustup.rs))
- `maturin` — Rust/Python build backend - automatically managed when using `pip install`

## Installing `spdk_psbt`

**Note:** Version 1.2 requires rust dependencies that are not yet published like PSBT_OUT_SCRIPT missing field - `rust-psbt script_pubkey: Option<ScriptBuf>`.
At this time using wheels is the easier solution to installing spdk_psbt - 3.14.2026
```bash
pip install --no-index --find-links wheels/ spdk_psbt
```

~~`spdk_psbt` is a Rust/uniffi Python extension. Its source lives in the `bip375-examples` repo under `rust/crates/spdk-uniffi`. Install it in editable mode, which compiles the Rust crate via maturin:~~

<del>
```bash
cd /path/to/bip375-examples/rust/crates/spdk-uniffi
pip install -e .
```
</del>

## Running the Generator

```bash
cd bip375-test-generator
pip install pyyaml
python test_generator.py
```

Output: `bip375_test_vectors.json`

### Vendored Bitcoin Core test_framework

Bitcoin transaction, script, sighash, signing, and secp256k1 primitives are
provided by a vendored snapshot of Bitcoin Core's `test/functional/test_framework`
in `test_framework/` (origin commit `d7ed2840ac`). `util.py` is trimmed to the
helpers the vendored modules actually use. Only the BIP-375 silent-payment
specifics remain custom in `generator_utils.py`.

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
    checks: [] # psbt_structure, ecdh_coverage, input_eligibility, output_scripts
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
jq -r '(.valid[], .invalid[]) | select(.supplementary.inputs != null) | .description, .supplementary.task, (.supplementary.inputs[] | "  input \(.input_index): signed=\(.signed)")' bip375_test_vectors.json
```
