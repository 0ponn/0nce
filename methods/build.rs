// Compiles the guest crate (methods/guest) with the RISC0 RISC-V toolchain
// and emits Rust bindings (the guest ELF + image ID) into OUT_DIR.
// See SPEC.md §4 for what the guest does.

fn main() {
    risc0_build::embed_methods();
}
