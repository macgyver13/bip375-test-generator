project_root := justfile_directory()
home := env_var("HOME")
vectors_file := "bip375_test_vectors.json"
out_dir := project_root + "/out"
bips_dir := home + "/src/bips/bip-0375"
spdk_dir := home + "/src/spdk/psbt/tests"
jade_dir := home + "/src/Jade/components/libwally-core/upstream/src/data"
# PSBT backend for every recipe: python (default) or spdk. Override with `just backend=spdk gen`.
backend := env_var_or_default("BIP375_PSBT_BACKEND", "py")
export BIP375_PSBT_BACKEND := backend

_default:
  @just --list

gen:
  @echo "Generating {{vectors_file}}"
  python {{project_root}}/test_generator.py

sync target:
  @case "{{target}}" in bip) just sync-bip ;; spdk) just sync-spdk ;; *) echo "Invalid sync target: {{target}}. Expected one of: bip, spdk" >&2; exit 1 ;; esac

sync-bip:
  @if [ ! -f {{project_root}}/{{vectors_file}} ]; then echo "Missing source file: {{project_root}}/{{vectors_file}}" >&2; exit 1; fi
  @if [ ! -d {{bips_dir}} ]; then echo "Missing destination directory: {{bips_dir}}" >&2; exit 1; fi
  @echo "Copying {{project_root}}/{{vectors_file}} -> {{bips_dir}}/{{vectors_file}}"
  cp {{project_root}}/{{vectors_file}} {{bips_dir}}/{{vectors_file}}

sync-spdk:
  @if [ ! -f {{project_root}}/{{vectors_file}} ]; then echo "Missing source file: {{project_root}}/{{vectors_file}}" >&2; exit 1; fi
  @if [ ! -d {{spdk_dir}} ]; then echo "Missing destination directory: {{spdk_dir}}" >&2; exit 1; fi
  @echo "Copying {{project_root}}/{{vectors_file}} -> {{spdk_dir}}/{{vectors_file}}"
  cp {{project_root}}/{{vectors_file}} {{spdk_dir}}/{{vectors_file}}

sync-jade:
  @if [ ! -f {{project_root}}/{{vectors_file}} ]; then echo "Missing source file: {{project_root}}/{{vectors_file}}" >&2; exit 1; fi
  @if [ ! -d {{jade_dir}} ]; then echo "Missing destination directory: {{jade_dir}}" >&2; exit 1; fi
  @echo "Copying {{project_root}}/{{vectors_file}} -> {{jade_dir}}/{{vectors_file}}"
  cp {{project_root}}/{{vectors_file}} {{jade_dir}}/{{vectors_file}}

sync-all:
  @just sync-bip
  @just sync-spdk

# Regenerate the vectors in each mutable revision of revs, oldest first, overwriting any conflicted copy.
regen-stack revs="@::":
  #!/usr/bin/env bash
  set -euo pipefail
  start=$(jj log --no-graph -r @ -T change_id)
  for rev in $(jj log --no-graph --reversed -r 'mutable() & ({{revs}})' -T 'change_id ++ "\n"'); do
    jj edit "$rev"
    python {{project_root}}/test_generator.py
  done
  jj edit "$start"

# Report semantic PSBT field changes between two jj revisions.
diff-vectors from="@-" to="@" verbosity="":
  python {{project_root}}/psbt_diff.py {{verbosity}} --jj "{{from}}" "{{to}}"

# Regenerate the vectors, require the committed file to match, and check every PSBT.
test:
  mkdir -p {{out_dir}}/test
  python {{project_root}}/test_generator.py --output {{out_dir}}/test/{{vectors_file}}
  cmp {{out_dir}}/test/{{vectors_file}} {{project_root}}/{{vectors_file}}
  python -m unittest discover -s {{project_root}}/tests

# Generate with the Python and Rust (spdk_psbt) backends into out/parity and require identical output.
test-parity:
  #!/usr/bin/env bash
  set -euo pipefail
  dir={{project_root}}/out/parity
  for backend in spdk py; do
    echo "== $backend"
    mkdir -p "$dir/$backend"
    BIP375_PSBT_BACKEND=$backend python {{project_root}}/test_generator.py --output "$dir/$backend/{{vectors_file}}"
  done
  diff -r "$dir/spdk" "$dir/py" && echo "parity OK: python and spdk backends match"
