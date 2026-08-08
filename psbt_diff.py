#!/usr/bin/env python3
"""Field-level diffs for base64 PSBTs and BIP-375 vector JSON files."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
from typing import Iterable


FIELD_NAMES = {
    "global": {
        0x00: "PSBT_GLOBAL_UNSIGNED_TX",
        0x01: "PSBT_GLOBAL_XPUB",
        0x02: "PSBT_GLOBAL_TX_VERSION",
        0x03: "PSBT_GLOBAL_FALLBACK_LOCKTIME",
        0x04: "PSBT_GLOBAL_INPUT_COUNT",
        0x05: "PSBT_GLOBAL_OUTPUT_COUNT",
        0x06: "PSBT_GLOBAL_TX_MODIFIABLE",
        0x07: "PSBT_GLOBAL_SP_ECDH_SHARE",
        0x08: "PSBT_GLOBAL_SP_DLEQ",
        0xFB: "PSBT_GLOBAL_VERSION",
        0xFC: "PSBT_GLOBAL_PROPRIETARY",
    },
    "input": {
        0x00: "PSBT_IN_NON_WITNESS_UTXO",
        0x01: "PSBT_IN_WITNESS_UTXO",
        0x02: "PSBT_IN_PARTIAL_SIG",
        0x03: "PSBT_IN_SIGHASH_TYPE",
        0x04: "PSBT_IN_REDEEM_SCRIPT",
        0x05: "PSBT_IN_WITNESS_SCRIPT",
        0x06: "PSBT_IN_BIP32_DERIVATION",
        0x07: "PSBT_IN_FINAL_SCRIPTSIG",
        0x08: "PSBT_IN_FINAL_SCRIPTWITNESS",
        0x0E: "PSBT_IN_PREVIOUS_TXID",
        0x0F: "PSBT_IN_OUTPUT_INDEX",
        0x10: "PSBT_IN_SEQUENCE",
        0x11: "PSBT_IN_REQUIRED_TIME_LOCKTIME",
        0x12: "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME",
        0x13: "PSBT_IN_TAP_KEY_SIG",
        0x14: "PSBT_IN_TAP_SCRIPT_SIG",
        0x15: "PSBT_IN_TAP_LEAF_SCRIPT",
        0x16: "PSBT_IN_TAP_BIP32_DERIVATION",
        0x17: "PSBT_IN_TAP_INTERNAL_KEY",
        0x18: "PSBT_IN_TAP_MERKLE_ROOT",
        0x1D: "PSBT_IN_SP_ECDH_SHARE",
        0x1E: "PSBT_IN_SP_DLEQ",
        0xFC: "PSBT_IN_PROPRIETARY",
    },
    "output": {
        0x00: "PSBT_OUT_REDEEM_SCRIPT",
        0x01: "PSBT_OUT_WITNESS_SCRIPT",
        0x02: "PSBT_OUT_BIP32_DERIVATION",
        0x03: "PSBT_OUT_AMOUNT",
        0x04: "PSBT_OUT_SCRIPT",
        0x05: "PSBT_OUT_TAP_INTERNAL_KEY",
        0x06: "PSBT_OUT_TAP_TREE",
        0x07: "PSBT_OUT_TAP_BIP32_DERIVATION",
        0x08: "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS",
        0x09: "PSBT_OUT_SP_V0_INFO",
        0x0A: "PSBT_OUT_SP_V0_LABEL",
        0xFC: "PSBT_OUT_PROPRIETARY",
    },
}


class PsbtDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class Field:
    scope: str
    index: int | None
    key: bytes
    value: bytes

    @property
    def type(self) -> int:
        return self.key[0]

    @property
    def location(self) -> str:
        return self.scope if self.index is None else f"{self.scope}[{self.index}]"

    @property
    def name(self) -> str:
        name = self.type_name
        if len(self.key) > 1:
            name += f"[keydata={short_hex(self.key[1:])}]"
        return name

    @property
    def type_name(self) -> str:
        return FIELD_NAMES[self.scope].get(self.type, f"UNKNOWN_0x{self.type:02x}")


@dataclass
class ParsedPsbt:
    raw: bytes
    fields: dict[tuple[str, int | None, bytes], Field]
    order: list[tuple[str, int | None, bytes]]


def compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset >= len(data):
        raise PsbtDecodeError("unexpected end while reading CompactSize")
    first = data[offset]
    sizes = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    if first < 0xFD:
        return first, offset + 1
    size = sizes[first]
    end = offset + 1 + size
    if end > len(data):
        raise PsbtDecodeError("truncated CompactSize")
    return int.from_bytes(data[offset + 1:end], "little"), end


def compact_size_value(data: bytes) -> int:
    value, end = compact_size(data)
    if end != len(data):
        raise PsbtDecodeError("trailing data after CompactSize")
    return value


def parse_psbt(encoded: str) -> ParsedPsbt:
    try:
        raw = base64.b64decode("".join(encoded.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PsbtDecodeError(f"invalid base64: {exc}") from exc
    if not raw.startswith(b"psbt\xff"):
        raise PsbtDecodeError("missing PSBT magic bytes")

    offset = 5
    fields: dict[tuple[str, int | None, bytes], Field] = {}
    order: list[tuple[str, int | None, bytes]] = []

    def read_map(scope: str, index: int | None = None) -> None:
        nonlocal offset
        while True:
            key_len, offset = compact_size(raw, offset)
            if key_len == 0:
                return
            key_end = offset + key_len
            if key_end > len(raw):
                raise PsbtDecodeError(f"truncated key in {scope} map")
            key = raw[offset:key_end]
            offset = key_end
            if not key:
                raise PsbtDecodeError(f"empty key in {scope} map")
            value_len, offset = compact_size(raw, offset)
            value_end = offset + value_len
            if value_end > len(raw):
                raise PsbtDecodeError(f"truncated value in {scope} map")
            value = raw[offset:value_end]
            offset = value_end
            identity = (scope, index, key)
            if identity in fields:
                raise PsbtDecodeError(f"duplicate key {key.hex()} in {scope} map")
            fields[identity] = Field(scope, index, key, value)
            order.append(identity)

    read_map("global")
    global_values = {field.type: field.value for field in fields.values()}
    try:
        input_count = compact_size_value(global_values[0x04])
        output_count = compact_size_value(global_values[0x05])
    except KeyError as exc:
        raise PsbtDecodeError("only PSBTv2 is supported (input/output count missing)") from exc
    for index in range(input_count):
        read_map("input", index)
    for index in range(output_count):
        read_map("output", index)
    if offset != len(raw):
        raise PsbtDecodeError(f"{len(raw) - offset} trailing byte(s) after PSBT maps")
    return ParsedPsbt(raw, fields, order)


def short_hex(value: bytes) -> str:
    text = value.hex()
    if len(value) <= 16:
        return text or "<empty>"
    digest = hashlib.sha256(value).hexdigest()[:12]
    return f"{text[:24]}… ({len(value)} bytes, sha256:{digest})"


def describe_value(field: Field) -> str:
    value = field.value
    field_type = field.type
    try:
        if field.scope == "global" and field_type in (0x04, 0x05):
            return str(compact_size_value(value))
        if (field.scope, field_type) in {
            ("global", 0x02), ("global", 0x03), ("global", 0xFB),
            ("input", 0x03), ("input", 0x0F), ("input", 0x10),
            ("input", 0x11), ("input", 0x12),
        } and len(value) == 4:
            return str(int.from_bytes(value, "little"))
        if field.scope == "global" and field_type == 0x06 and len(value) == 1:
            return f"0x{value[0]:02x}"
        if field.scope == "input" and field_type == 0x0E and len(value) == 32:
            return value[::-1].hex() + " (txid)"
        if field.scope == "output" and field_type == 0x03 and len(value) == 8:
            return f"{int.from_bytes(value, 'little')} sat"
        if field.scope == "input" and field_type == 0x01 and len(value) >= 9:
            amount = int.from_bytes(value[:8], "little")
            script_len, start = compact_size(value, 8)
            if start + script_len == len(value):
                return f"amount={amount} sat, script={value[start:].hex()}"
    except PsbtDecodeError:
        pass
    return short_hex(value)


def field_sort_key(identity: tuple[str, int | None, bytes]) -> tuple[int, int, bytes]:
    scope, index, key = identity
    return ({"global": 0, "input": 1, "output": 2}[scope], index or 0, key)


def order_changes(old: ParsedPsbt, new: ParsedPsbt, verbosity: int) -> list[str]:
    """Describe map order changes after field/value equivalence is established."""
    locations = sorted(
        {(scope, index) for scope, index, _ in old.order},
        key=lambda item: field_sort_key((item[0], item[1], b"")),
    )
    changes = []
    for location in locations:
        old_order = [identity for identity in old.order if identity[:2] == location]
        new_order = [identity for identity in new.order if identity[:2] == location]
        if old_order == new_order:
            continue
        scope, index = location
        label = scope if index is None else f"{scope}[{index}]"
        if verbosity == 1:
            old_types = " -> ".join(f"0x{old.fields[item].type:02x}" for item in old_order)
            new_types = " -> ".join(f"0x{new.fields[item].type:02x}" for item in new_order)
            changes.append(f"  {label} old: {old_types}")
            changes.append(f"  {label} new: {new_types}")
        else:
            old_names = " -> ".join(old.fields[item].name for item in old_order)
            new_names = " -> ".join(new.fields[item].name for item in new_order)
            changes.append(f"  {label} old: {old_names}")
            changes.append(f"  {label} new: {new_names}")
    return changes


def diff_psbts(old_text: str, new_text: str, verbosity: int = 0) -> list[str]:
    old = parse_psbt(old_text)
    new = parse_psbt(new_text)
    differences: list[tuple[str, Field, Field | None]] = []
    identities = sorted(old.fields.keys() | new.fields.keys(), key=field_sort_key)
    for identity in identities:
        before = old.fields.get(identity)
        after = new.fields.get(identity)
        sample = before or after
        assert sample is not None
        if before is None:
            differences.append(("+", after, None))
        elif after is None:
            differences.append(("-", before, None))
        elif before.value != after.value:
            differences.append(("~", before, after))

    if differences:
        if verbosity == 0:
            return ["! PSBT maps are not equivalent"]
        lines = []
        for operation, field, after in differences:
            if verbosity == 1:
                lines.append(
                    f"{operation} {field.location} 0x{field.type:02x} {field.type_name}"
                )
            elif operation == "~":
                assert after is not None
                lines.append(
                    f"~ {field.location} {field.name}: "
                    f"{describe_value(field)} -> {describe_value(after)}"
                )
            else:
                lines.append(f"{operation} {field.location} {field.name}: {describe_value(field)}")
        return lines

    lines: list[str] = []
    if verbosity and old.raw != new.raw:
        reordered = order_changes(old, new, verbosity)
        if reordered:
            lines.append("= maps equivalent; serialization order changed only")
            lines.extend(reordered)
        else:
            lines.append("= maps equivalent; byte encoding changed without a field-order change")
    return lines


def vector_cases(document: dict) -> dict[tuple[str, str], str]:
    cases = {}
    for section in ("valid", "invalid"):
        for case in document.get(section, []):
            identity = (section, case["description"])
            if identity in cases:
                raise ValueError(f"duplicate {section} description: {case['description']}")
            cases[identity] = case["psbt"]
    return cases


def diff_documents(
    old: dict,
    new: dict,
    verbosity: int = 0,
    description_filter: str | None = None,
) -> list[str]:
    old_cases, new_cases = vector_cases(old), vector_cases(new)
    output: list[str] = []
    identities = old_cases.keys() | new_cases.keys()
    if description_filter is not None:
        identities = {
            identity for identity in identities if description_filter in identity[1]
        }
        if not identities:
            return [f"No vector descriptions matched filter: {description_filter}"]
    for identity in sorted(identities):
        section, description = identity
        if identity not in old_cases:
            output.append(f"+ [{section}] {description} (new vector)")
            continue
        if identity not in new_cases:
            output.append(f"- [{section}] {description} (removed vector)")
            continue
        changes = diff_psbts(old_cases[identity], new_cases[identity], verbosity)
        if changes:
            output.append(f"[{section}] {description}")
            output.extend(f"  {line}" for line in changes)
    return output


def load_source(source: str) -> tuple[str, object]:
    # Avoid stat(2) on long base64 strings (which can fail with ENAMETOOLONG).
    if source.lstrip().startswith("cHNidP"):
        return "psbt", source
    path = Path(source)
    try:
        is_file = path.is_file()
    except OSError:
        is_file = False
    if is_file:
        text = path.read_text()
        try:
            return "json", json.loads(text)
        except json.JSONDecodeError:
            return "psbt", text.strip()
    return "psbt", source


def jj_json(revision: str, path: str) -> dict:
    result = subprocess.run(
        ["jj", "file", "show", "-r", revision, path],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old", nargs="?", help="old base64 PSBT or JSON/file")
    parser.add_argument("new", nargs="?", help="new base64 PSBT or JSON/file")
    parser.add_argument(
        "--jj", nargs=2, metavar=("OLD_REV", "NEW_REV"),
        help="compare bip375_test_vectors.json at two jj revisions",
    )
    parser.add_argument("--file", default="bip375_test_vectors.json", help="path used with --jj")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="show field types; repeat (-vv) to include values and complete ordering",
    )
    parser.add_argument(
        "-f", "--filter", metavar="STRING",
        help="only compare vectors whose description contains STRING",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.jj:
            if args.old or args.new:
                raise ValueError("positional sources cannot be combined with --jj")
            lines = diff_documents(
                jj_json(args.jj[0], args.file),
                jj_json(args.jj[1], args.file),
                min(args.verbose, 2),
                args.filter,
            )
        else:
            if not args.old or not args.new:
                raise ValueError("provide OLD and NEW sources, or use --jj OLD_REV NEW_REV")
            old_kind, old = load_source(args.old)
            new_kind, new = load_source(args.new)
            if old_kind != new_kind:
                raise ValueError("both sources must be the same kind (PSBT or JSON)")
            if old_kind == "psbt" and args.filter is not None:
                raise ValueError("--filter requires JSON files or --jj")
            verbosity = min(args.verbose, 2)
            lines = (
                diff_documents(old, new, verbosity, args.filter)
                if old_kind == "json"
                else diff_psbts(old, new, verbosity)
            )
        print("\n".join(lines) if lines else "All compared PSBT maps are equivalent.")
        return 0
    except (OSError, ValueError, PsbtDecodeError, subprocess.CalledProcessError) as exc:
        print(f"psbt-diff: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
