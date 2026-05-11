//! Auto-generated bindings to the guest ELF and image ID, via `risc0-build`.
//! The host crate depends on this and uses the embedded ELF + image ID to
//! invoke the prover. See SPEC.md §4.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
