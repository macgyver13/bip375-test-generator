project_root := justfile_directory()
home := env_var("HOME")
vectors_file := "bip375_test_vectors.json"
bips_dir := home + "/src/bips/bip-0375"
spdk_dir := home + "/src/spdk/psbt/tests"
jade_dir := home + "/src/Jade/components/libwally-core/upstream/src/data"

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

# Report semantic PSBT field changes between two jj revisions.
diff-vectors from="@-" to="@" verbosity="":
  python {{project_root}}/psbt_diff.py {{verbosity}} --jj "{{from}}" "{{to}}"
