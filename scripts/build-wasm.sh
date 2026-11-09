#!/usr/bin/env bash
# This file keeps its declarations with the functions they describe.
# dyshellint disable=BSG033
# @file build-wasm.sh
# @brief Build dybw-core-wasm for the web
# @description Builds the crate with the `wasm` profile, generates the `--target web` glue with wasm-bindgen,
#              shrinks the module with `wasm-opt -Oz` (the features rustc enables for wasm32), then refuses glue a
#              bundle cannot take (D13), and prints the size report (D12): the module, its base64, the glue after
#              esbuild minify, gzip (information) and the total against the budget of 1 179 648 bytes for
#              base64(wasm) + glue, which `js/test/size.test.ts` enforces. The report needs node and the harness's
#              `npm ci` (esbuild). `WASM_OPT` names the wasm-opt binary; dybatpho is found at `DYBATPHO_DIR`.
SCRIPT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
ROOT="$(dirname "${SCRIPT_DIR}")"
: "${DYBATPHO_DIR:=${HOME}/Working/personal/tools/dybatpho}"
# shellcheck source=/dev/null
. "${DYBATPHO_DIR}/init.sh" --modules cli || exit 1

dybatpho::register_common_handlers

# Set by the option parser.
FEATURES=""
OUT=""

# What the glue must not contain: Node-only or eval-like code, and `import.meta` (esbuild's cjs output drops it).
FORBIDDEN=('require(' 'process.' 'Buffer.' 'eval(' 'new Function(' 'import.meta')

# @description Builds, binds, optimizes and checks the glue.
# @noargs
function _build {
  local _opt="${WASM_OPT:-wasm-opt}"
  dybatpho::require cargo
  dybatpho::require rustc
  dybatpho::require wasm-bindgen
  dybatpho::require "${_opt}"
  dybatpho::require node

  local -a _features=()
  if [[ -n "${FEATURES}" ]]; then
    _features=(--features "${FEATURES}")
  fi
  # No absolute build path in the module (panic locations): the repository, the registry sources and the sysroot.
  local _registry="${CARGO_HOME:-${HOME}/.cargo}/registry/src" _sysroot
  _sysroot="$(rustc --print sysroot)" || dybatpho::die "rustc cannot print its sysroot"
  export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--remap-path-prefix=${ROOT}=dybw-core \
--remap-path-prefix=${_registry}=registry --remap-path-prefix=${_sysroot}=rustc"
  dybatpho::info "Building dybw-core-wasm"
  cargo build -p dybw-core-wasm --profile wasm --target wasm32-unknown-unknown --locked \
    --manifest-path "${ROOT}/Cargo.toml" ${_features[@]+"${_features[@]}"}

  local _target="${CARGO_TARGET_DIR:-${ROOT}/target}"
  # No default module path: it is `import.meta.url`; the host passes the module to `initSync`.
  wasm-bindgen --target web --omit-default-module-path --out-dir "${OUT}" \
    "${_target}/wasm32-unknown-unknown/wasm/dybw_core_wasm.wasm"

  local _wasm="${OUT}/dybw_core_wasm_bg.wasm"
  "${_opt}" -Oz --enable-bulk-memory --enable-multivalue --enable-mutable-globals \
    --enable-nontrapping-float-to-int --enable-reference-types --enable-sign-ext -o "${_wasm}" "${_wasm}"

  local _glue="${OUT}/dybw_core_wasm.js" _found _pattern
  for _pattern in "${FORBIDDEN[@]}"; do
    _found="$(grep -nF -- "${_pattern}" "${_glue}" || true)"
    [[ -z "${_found}" ]] || dybatpho::die "The glue contains ${_pattern}: ${_found}"
  done
  dybatpho::info "Size report"
  node "${ROOT}/crates/dybw-core-wasm/js/size.mjs" "${OUT}"
  [[ -z "${FEATURES}" ]] || dybatpho::warn "Built with features: the budget applies to the build without them"
  dybatpho::success "Built ${_wasm}"
}

# @description The option spec of the build.
# @noargs
function _spec {
  dybatpho::opts::setup "Build dybw-core-wasm for the web" ARGS action:"_build"
  dybatpho::opts::param "Cargo features to enable, e.g. vectors" FEATURES --features init:=""
  dybatpho::opts::param "Output directory" OUT --out init:="${ROOT}/target-wasm/pkg"
  dybatpho::opts::disp "Show help" --help -h action:"dybatpho::generate_help _spec"
}

dybatpho::generate_from_spec _spec "$@"
