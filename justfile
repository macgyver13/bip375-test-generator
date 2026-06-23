project_root := justfile_directory()
home := env_var("HOME")
vectors_file := "bip375_test_vectors.json"
rust_vectors_file := "bip375.json"
bips_dir := home + "/src/bips/bip-0375"
rust_psbt_dir := home + "/src/rust-psbt"
examples_dir := home + "/src/bip375-examples"
convert_script := project_root + "/convert_to_rust_bip375_format.py"

_default:
  @just --list

gen:
  @echo "Generating {{vectors_file}}"
  python {{project_root}}/test_generator.py

gen-rust:
  @if [ ! -f {{project_root}}/{{vectors_file}} ]; then echo "Missing source file: {{project_root}}/{{vectors_file}}" >&2; exit 1; fi
  @if [ ! -f {{convert_script}} ]; then echo "Missing conversion script: {{convert_script}}" >&2; exit 1; fi
  @echo "Generating {{rust_vectors_file}} from {{vectors_file}}"
  python {{convert_script}} {{project_root}}/{{vectors_file}} -o {{project_root}}/{{rust_vectors_file}}

# Report semantic PSBT field changes between two jj revisions.
diff-vectors from="@-" to="@" verbosity="":
  python {{project_root}}/psbt_diff.py {{verbosity}} --jj "{{from}}" "{{to}}"

sync target:
  @case "{{target}}" in bip) just sync-bip ;; rust) just sync-rust ;; example) just sync-example ;; *) echo "Invalid sync target: {{target}}. Expected one of: bip, rust, example" >&2; exit 1 ;; esac

sync-bip:
  @if [ ! -f {{project_root}}/{{vectors_file}} ]; then echo "Missing source file: {{project_root}}/{{vectors_file}}" >&2; exit 1; fi
  @if [ ! -d {{bips_dir}} ]; then echo "Missing destination directory: {{bips_dir}}" >&2; exit 1; fi
  @echo "Copying {{project_root}}/{{vectors_file}} -> {{bips_dir}}/{{vectors_file}}"
  cp {{project_root}}/{{vectors_file}} {{bips_dir}}/{{vectors_file}}

sync-rust:
  @if [ ! -f {{project_root}}/{{vectors_file}} ]; then echo "Missing source file: {{project_root}}/{{vectors_file}}" >&2; exit 1; fi
  @if [ ! -f {{convert_script}} ]; then echo "Missing conversion script: {{convert_script}}" >&2; exit 1; fi
  @if [ ! -d {{rust_psbt_dir}}/tests/data ]; then echo "Missing destination directory: {{rust_psbt_dir}}/tests/data" >&2; exit 1; fi
  @echo "Generating {{project_root}}/{{rust_vectors_file}} from {{project_root}}/{{vectors_file}}"
  python {{convert_script}} {{project_root}}/{{vectors_file}} -o {{project_root}}/{{rust_vectors_file}}
  @if [ ! -f {{project_root}}/{{rust_vectors_file}} ]; then echo "Missing generated file: {{project_root}}/{{rust_vectors_file}}" >&2; exit 1; fi
  @echo "Copying {{project_root}}/{{rust_vectors_file}} -> {{rust_psbt_dir}}/tests/data/{{rust_vectors_file}}"
  cp {{project_root}}/{{rust_vectors_file}} {{rust_psbt_dir}}/tests/data/{{rust_vectors_file}}

sync-example:
  @if [ ! -f {{project_root}}/{{vectors_file}} ]; then echo "Missing source file: {{project_root}}/{{vectors_file}}" >&2; exit 1; fi
  @if [ ! -d {{examples_dir}} ]; then echo "Missing destination directory: {{examples_dir}}" >&2; exit 1; fi
  @echo "Copying {{project_root}}/{{vectors_file}} -> {{examples_dir}}/{{vectors_file}}"
  cp {{project_root}}/{{vectors_file}} {{examples_dir}}/{{vectors_file}}

sync-all:
  @just sync-bip
  @just sync-rust
  @just sync-example
