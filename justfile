project_root := justfile_directory()
home := env_var("HOME")
vectors_file := "bip375_test_vectors.json"
# The standard vectors plus every optional set (see INCLUDE_CHOICES in test_generator.py)
extended_file := "bip375_test_vectors_extended.json"
extended_includes := "workflows,experimental"
rust_vectors_file := "bip375.json"
out_dir := project_root + "/out"
bips_dir := home + "/src/bips/bip-0375"
rust_psbt_dir := home + "/src/rust-psbt"
spdk_dir := home + "/src/spdk/psbt/tests"
jade_dir := home + "/src/Jade/components/libwally-core/upstream/src/data"
jade_fixtures_dir := home + "/src/Jade/test_data"
convert_script := project_root + "/convert_to_rust_bip375_format.py"
# PSBT backend for every recipe: python (default) or spdk. Override with `just backend=spdk gen`.
backend := env_var_or_default("BIP375_PSBT_BACKEND", "py")
export BIP375_PSBT_BACKEND := backend
# Revision (bookmark or change id) whose scripts gen and sync run, e.g. `just rev=bips/validator-hardening sync bip`.
# Empty means the working copy.
rev := ""

_default:
  @just --list

# extended is standard plus extended_includes. jade is Jade's keys and device cases, plus one
# fixture file per case. standard and extended also get the rust-psbt export. With rev set, the
# scripts come from that revision's tree and the output goes to out/at/<rev>/<tier>.
[doc("Generate a tier (standard, extended, jade) into out/<tier>, from rev when given. Plain `just gen` also rewrites the committed file.")]
gen tier="standard":
  #!/usr/bin/env bash
  set -euo pipefail
  root={{project_root}}
  dir={{out_dir}}/{{tier}}
  if [ -n "{{rev}}" ]; then
    commit=$(jj log --no-graph -r '{{rev}}' -T commit_id)
    root=$(mktemp -d)
    trap 'rm -rf "$root"' EXIT
    git --git-dir="$(jj git root)" archive "$commit" | tar -x -C "$root"
    dir={{out_dir}}/at/{{rev}}/{{tier}}
  fi
  case "{{tier}}" in
    standard) flags="" ;;
    extended) flags="--include {{extended_includes}}" ;;
    jade) flags="--key-profile jade --include jade" ;;
    *) echo "Invalid tier: {{tier}}. Expected one of: standard, extended, jade" >&2; exit 1 ;;
  esac
  mkdir -p "$dir"
  echo "Generating $dir/{{vectors_file}} ({{tier}}) from ${commit:-the working copy}"
  python "$root/test_generator.py" $flags --output "$dir/{{vectors_file}}"
  if [ "{{tier}}" = jade ]; then
    rm -f "$dir"/psbt_sp_375_*.json
    python "$root/convert_to_jade_fixtures.py" "$dir/{{vectors_file}}" -o "$dir"
  else
    python "$root/convert_to_rust_bip375_format.py" "$dir/{{vectors_file}}" -o "$dir/{{rust_vectors_file}}"
  fi
  if [ "{{tier}}" = standard ] && [ -z "{{rev}}" ]; then
    cp "$dir/{{vectors_file}}" {{project_root}}/{{vectors_file}}
  fi

# Targets: bip, rust, spdk, jade, jade-fixtures. tier overrides the target's default.
[doc("Generate a target's tier (from rev when given) and copy it into the target's repo.")]
sync target tier="":
  #!/usr/bin/env bash
  set -euo pipefail
  case "{{target}}" in
    bip) default=standard; dest={{bips_dir}} ;;
    rust) default=extended; dest={{rust_psbt_dir}}/tests/data ;;
    spdk) default=extended; dest={{spdk_dir}} ;;
    jade) default=extended; dest={{jade_dir}} ;;
    jade-fixtures) default=jade; dest={{jade_fixtures_dir}} ;;
    *) echo "Invalid sync target: {{target}}. Expected one of: bip, rust, spdk, jade, jade-fixtures" >&2; exit 1 ;;
  esac
  tier="{{tier}}"
  tier=${tier:-$default}
  if [ ! -d "$dest" ]; then echo "Missing destination directory: $dest" >&2; exit 1; fi
  just rev="{{rev}}" gen "$tier"
  dir={{out_dir}}/$tier
  if [ -n "{{rev}}" ]; then dir={{out_dir}}/at/{{rev}}/$tier; fi
  case "{{target}}" in
    rust) src=$dir/{{rust_vectors_file}} ;;
    jade-fixtures)
      echo "Removing stale psbt_sp_375_*.json in $dest"
      rm -f "$dest"/psbt_sp_375_*.json
      echo "Copying $dir/psbt_sp_375_*.json -> $dest/"
      cp "$dir"/psbt_sp_375_*.json "$dest"/
      exit 0 ;;
    *) src=$dir/{{vectors_file}} ;;
  esac
  echo "Copying $src -> $dest/$(basename "$src")"
  cp "$src" "$dest"/

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

# Regenerate the standard file and require the committed copy to match, generate the extended file, export it for rust-psbt, generate the jade fixtures, and check every PSBT.
test:
  mkdir -p {{out_dir}}/test
  python {{project_root}}/test_generator.py --output {{out_dir}}/test/{{vectors_file}}
  cmp {{out_dir}}/test/{{vectors_file}} {{project_root}}/{{vectors_file}}
  @just gen extended
  @just gen jade
  python -m unittest discover -s {{project_root}}/tests

# Generate with the Python and Rust (spdk_psbt) backends into out/parity and require identical output.
test-parity:
  #!/usr/bin/env bash
  set -euo pipefail
  dir={{out_dir}}/parity
  for backend in spdk py; do
    echo "== $backend"
    mkdir -p "$dir/$backend"
    BIP375_PSBT_BACKEND=$backend python {{project_root}}/test_generator.py --output "$dir/$backend/{{vectors_file}}"
    BIP375_PSBT_BACKEND=$backend python {{project_root}}/test_generator.py --include {{extended_includes}} --output "$dir/$backend/{{extended_file}}"
    BIP375_PSBT_BACKEND=$backend python {{convert_script}} "$dir/$backend/{{extended_file}}" -o "$dir/$backend/{{rust_vectors_file}}"
  done
  diff -r "$dir/spdk" "$dir/py" && echo "parity OK: python and spdk backends match"
