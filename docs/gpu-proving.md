# GPU proving (RISC0 CUDA) — setup

Proving 0nce on an NVIDIA GPU instead of CPU. Measured on this box (RTX 4070 Ti
SUPER, 16 GB): the `real.eml` prod prove drops from **27:02 (CPU, i5-11600K) to
0:12 (GPU)** — ~135×, host RAM 9.6 GB → 0.6 GB — with the proof **byte-identical**
and the nullifier unchanged (`20939a2d…`). GPU confirmed at 90–100% util, ~12 GB
VRAM peak (fits 16 GB).

The whole CUDA build toolchain is **userspace and isolated** — it touches no system
package and not the NVIDIA driver. Build-time uses a conda env in `~/.local/cuda-zk`;
run-time links the system driver's `libcuda`. Delete the env and the box is unchanged.

## Why isolated (the Fedora-44 problem)

This box runs Fedora 44 with **GCC 16** and the **driver's** CUDA runtime libs, but
no CUDA Toolkit (`nvcc`). RISC0's `cuda` feature must *compile* CUDA kernels, which
needs `nvcc` + a CUDA-compatible host compiler (≤ GCC 13). Installing the toolkit
system-wide on bleeding-edge Fedora risks driver conflicts, so instead we bring an
isolated CUDA 12.6 + GCC 13 toolchain via micromamba.

## One-time setup

```sh
ROOT=~/.local/cuda-zk
mkdir -p "$ROOT/bin" && cd "$ROOT"
# micromamba (single static binary, userspace)
curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest | tar -xj -C "$ROOT" bin/micromamba
export MAMBA_ROOT_PREFIX="$ROOT"
# isolated CUDA 12.6 toolchain + its own gcc-13 (matches what nvcc accepts)
./bin/micromamba create -y -p ./envs/cuda126 -c conda-forge \
  cuda-version=12.6 cuda-nvcc cuda-cudart-dev cuda-cccl cuda-driver-dev gxx_linux-64=13
# prebuilt protoc (a build dep in the CUDA tree)
curl -Ls -o protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v25.3/protoc-25.3-linux-x86_64.zip
python3 -c "import zipfile; zipfile.ZipFile('protoc.zip').extractall('protoc')" && chmod +x protoc/bin/protoc
# cc/c++ shim -> conda gcc-13 (so RISC0's hardcoded `-ccbin=c++` doesn't grab system gcc-16)
mkdir -p "$ROOT/shim"
ln -sfn envs/cuda126/bin/x86_64-conda-linux-gnu-g++ "$ROOT/shim/c++"
ln -sfn envs/cuda126/bin/x86_64-conda-linux-gnu-g++ "$ROOT/shim/g++"
ln -sfn envs/cuda126/bin/x86_64-conda-linux-gnu-gcc "$ROOT/shim/cc"
ln -sfn envs/cuda126/bin/x86_64-conda-linux-gnu-gcc "$ROOT/shim/gcc"
```

## Environment (source before build / prove)

```sh
ENV=~/.local/cuda-zk/envs/cuda126; SHIM=~/.local/cuda-zk/shim
export CUDA_HOME="$ENV"
export CUDA_PATH="$ENV/targets/x86_64-linux"        # headers: find_cuda_root wants <root>/include/cuda.h
export CUDA_ROOT="$CUDA_PATH" CUDA_TOOLKIT_ROOT_DIR="$CUDA_PATH"
export CUDA_LIBRARY_PATH="$ENV"                      # libs: find_cuda_lib_dirs keys off targets/.../include/cuda.h
export PATH="$SHIM:$ENV/bin:$HOME/.risc0/bin:$PATH"  # SHIM first -> cc/c++ are gcc-13
export CC="$ENV/bin/x86_64-conda-linux-gnu-gcc" CXX="$ENV/bin/x86_64-conda-linux-gnu-g++"
export CFLAGS="-DNDEBUG" CXXFLAGS="-DNDEBUG"         # strip device asserts (sppark + newer glibc clash)
export PROTOC="$HOME/.local/cuda-zk/protoc/bin/protoc"
export LD_LIBRARY_PATH="$ENV/lib:$ENV/targets/x86_64-linux/lib:${LD_LIBRARY_PATH:-}"
```

## Build & prove

```sh
cargo build --release --bin 0nce --features cuda     # ~20 min first time (compiles CUDA kernels)
ldd target/release/0nce | grep libcuda               # should resolve to /lib64/libcuda.so.1 (system driver)
./target/release/0nce prove --email host/tests/fixtures/real.eml \
  --pubkey-tag "$(cat host/tests/fixtures/real.pubkey.tag)" -y --out /tmp/p.bin
```

CPU proving stays the default and needs **none** of the above — just omit
`--features cuda`.

## The four Fedora-44 gotchas (in case the toolchain layout shifts)

1. **CUDA path discovery.** `find_cuda_helper` expects `/usr/local/cuda`-style
   `lib64`; conda uses `lib` under `targets/x86_64-linux/`. Fixed by `CUDA_ROOT` →
   `targets/x86_64-linux` (has `include/cuda.h`) and `CUDA_LIBRARY_PATH` → the env
   prefix.
2. **`-ccbin=c++` → GCC 16.** `risc0-sys` hardcodes `-ccbin=c++`, overriding
   `NVCC_PREPEND_FLAGS` (nvcc takes the last `-ccbin`). Fixed by a PATH shim making
   `c++`/`cc` the conda gcc-13.
3. **Device asserts.** `sppark`'s BN254 NTT calls `assert` → `__host__ __assert_fail`
   from device code under newer glibc. Fixed by `-DNDEBUG` (correct for release).
4. **`protoc` missing.** A protobuf build dep in the CUDA tree; provided by a prebuilt
   static `protoc` + `PROTOC`.

## Notes

- RISC0 3.0.5 + CUDA 12.6 (driver 595.80 supports up to 13.2; backward-compatible).
- The `cuda` feature compiles `risc0-groth16-sys` CUDA code even though 0nce produces
  a STARK receipt (not Groth16) — it builds but isn't used at prove time.
- Heavier proofs (v2-B/C DNSSEC chains) are exactly where this pays off; 12 s leaves
  ample VRAM headroom for more in-STARK work.
