//! v2-A registry leaf + Merkle membership.
//!
//! Shared by the guest (which proves a witnessed DKIM key is a registry
//! member) and the host (which builds the tree). The **leaf** is a BN254
//! Poseidon hash (`light-poseidon`, Circom/Iden3 params) of each
//! variable-length input compressed to one field element via SHA-256 then
//! reduced mod the field order — same primitive as the nullifier, so it stays
//! Circom-compatible. The **node** hash (2-to-1 compression up the tree) is
//! SHA-256: a BN254 Poseidon node ran as unaccelerated software bignum in the
//! RISC0 guest and 4×'d prove time (BENCHMARKS.md 2026-06-15); SHA-256 rides
//! the accelerator and is ~2 orders cheaper. Only the tree shape changed —
//! leaf semantics are unaffected.
//!
//! Leaf semantics are LOCKED at v2-A and must not change in v2-C — C may swap
//! the tree shape (e.g. to an indexed tree for revocation) but a leaf always
//! means `Poseidon(sep, domain, selector, n, e)`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use sha2::{Digest, Sha256};

/// Domain separator for the registry leaf. Locked; distinct from the
/// nullifier separator so leaves and nullifiers never collide.
pub const DOMAIN_SEPARATOR_REGISTRY_V2: &[u8] = b"0nce-v2-registry-leaf";

/// Fixed Merkle depth. A path is exactly this many siblings; the guest
/// rejects any other length (prevents path-length-ambiguity forgeries).
/// 2^20 ≈ 1.05M keys — ample for any realistic DKIM-key set.
pub const REGISTRY_DEPTH: usize = 20;

/// Compress arbitrary-length bytes to one BN254 field element (same scheme as
/// the nullifier: SHA-256 then reduce mod order).
fn bytes_to_field(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(&Sha256::digest(bytes))
}

fn fr_to_bytes(f: Fr) -> [u8; 32] {
    let be = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// `leaf = Poseidon(sep, domain, selector, n, e)`.
pub fn registry_leaf(domain: &[u8], selector: &[u8], pubkey_n: &[u8], pubkey_e: &[u8]) -> [u8; 32] {
    let inputs = [
        bytes_to_field(DOMAIN_SEPARATOR_REGISTRY_V2),
        bytes_to_field(domain),
        bytes_to_field(selector),
        bytes_to_field(pubkey_n),
        bytes_to_field(pubkey_e),
    ];
    let mut h = Poseidon::<Fr>::new_circom(5).expect("poseidon init t=6");
    fr_to_bytes(h.hash(&inputs).expect("poseidon hash (leaf)"))
}

/// 2-to-1 Merkle compression `node = SHA-256(left || right)`.
///
/// SHA-256 (not BN254 Poseidon) so the fold rides the RISC0 SHA accelerator
/// instead of unaccelerated bignum — see the module note and BENCHMARKS.md.
/// Untagged 64-byte input matches the original untagged Poseidon(l,r). Leaf/node
/// confusion is defeated not by a domain byte but by three properties enforced
/// together (independent soundness audit, 2026-06-25): fixed-depth verification
/// (the fold is always exactly `REGISTRY_DEPTH` hashes, so no variable-depth
/// re-labeling of an internal node as a leaf), in-circuit leaf derivation (the
/// guest computes the leaf via `registry_leaf`, so a prover can't submit an
/// arbitrary 32-byte node value as a leaf), and SHA-256 second-preimage
/// resistance. The `leaf_index < 2^DEPTH` check is witness hygiene, not the
/// load-bearing defense.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Domain-separated empty-leaf constant for padding unused slots.
pub fn empty_leaf() -> [u8; 32] {
    let mut h = Poseidon::<Fr>::new_circom(1).expect("poseidon init t=2");
    fr_to_bytes(
        h.hash(&[bytes_to_field(b"0nce-v2-registry-empty")])
            .expect("poseidon hash (empty)"),
    )
}

/// Verify that `leaf` at `leaf_index` authenticates to `root` via `path`.
/// `path[i]` is the sibling at level `i` (leaf level = 0). The bit `i` of
/// `leaf_index` selects whether the running node is the left (0) or right (1)
/// child at that level.
pub fn verify_membership(
    leaf: &[u8; 32],
    path: &[[u8; 32]],
    leaf_index: u32,
    root: &[u8; 32],
) -> bool {
    if path.len() != REGISTRY_DEPTH {
        return false;
    }
    // Witness hygiene: only the low REGISTRY_DEPTH bits of leaf_index are
    // consumed by the fold; reject anything that sets higher bits so the
    // index is unambiguous (no soundness impact — the fold is already pinned
    // by leaf + siblings — but it removes a malleable witness.)
    if (leaf_index as u64) >= (1u64 << REGISTRY_DEPTH) {
        return false;
    }
    let mut node = *leaf;
    for (level, sibling) in path.iter().enumerate() {
        node = if (leaf_index >> level) & 1 == 0 {
            node_hash(&node, sibling)
        } else {
            node_hash(sibling, &node)
        };
    }
    &node == root
}

/// A built fixed-depth Merkle tree over a contiguous prefix of real leaves
/// (indices `0..leaves.len()`), with all remaining slots = `empty_leaf()`.
pub struct RegistryTree {
    /// `layers[0]` = the real-leaf prefix; `layers[REGISTRY_DEPTH]` = `[root]`.
    layers: Vec<Vec<[u8; 32]>>,
    /// Precomputed empty-subtree hash per level (`empties[0] == empty_leaf()`).
    empties: Vec<[u8; 32]>,
}

impl RegistryTree {
    /// Build the tree from real leaves placed at indices `0..leaves.len()`.
    pub fn build(leaves: Vec<[u8; 32]>) -> Self {
        let mut empties = Vec::with_capacity(REGISTRY_DEPTH + 1);
        empties.push(empty_leaf());
        for level in 0..REGISTRY_DEPTH {
            let e = empties[level];
            empties.push(node_hash(&e, &e));
        }

        let mut layers: Vec<Vec<[u8; 32]>> = Vec::with_capacity(REGISTRY_DEPTH + 1);
        layers.push(leaves);
        for level in 0..REGISTRY_DEPTH {
            let cur = &layers[level];
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = cur.get(i + 1).copied().unwrap_or(empties[level]);
                next.push(node_hash(&left, &right));
                i += 2;
            }
            if next.is_empty() {
                next.push(empties[level + 1]);
            }
            layers.push(next);
        }
        RegistryTree { layers, empties }
    }

    pub fn root(&self) -> [u8; 32] {
        self.layers[REGISTRY_DEPTH][0]
    }

    /// The authentication path (siblings, level 0 upward) for a leaf index.
    pub fn path(&self, leaf_index: usize) -> Vec<[u8; 32]> {
        let mut path = Vec::with_capacity(REGISTRY_DEPTH);
        let mut idx = leaf_index;
        for level in 0..REGISTRY_DEPTH {
            let sib = idx ^ 1;
            let h = self.layers[level].get(sib).copied().unwrap_or(self.empties[level]);
            path.push(h);
            idx >>= 1;
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(d: &[u8]) -> [u8; 32] {
        registry_leaf(d, b"sel", b"modulus", b"\x01\x00\x01")
    }

    #[test]
    fn node_hash_is_sha256_of_concatenation() {
        // Pin the node primitive: SHA-256(left || right). Guards against a
        // silent regression back to BN254 Poseidon (the 4× prove-time cause).
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let mut expected = Sha256::new();
        expected.update(left);
        expected.update(right);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(node_hash(&left, &right), expected);
        assert_ne!(node_hash(&left, &right), node_hash(&right, &left));
    }

    #[test]
    fn leaf_is_deterministic_and_domain_sensitive() {
        assert_eq!(leaf(b"a.test"), leaf(b"a.test"));
        assert_ne!(leaf(b"a.test"), leaf(b"b.test"));
    }

    #[test]
    fn leaf_sensitive_to_pubkey() {
        let a = registry_leaf(b"a.test", b"s", b"n1", b"\x01\x00\x01");
        let b = registry_leaf(b"a.test", b"s", b"n2", b"\x01\x00\x01");
        assert_ne!(a, b);
    }

    #[test]
    fn build_then_verify_roundtrips_for_every_leaf() {
        let leaves: Vec<_> = (0u8..5).map(|i| leaf(&[b'd', i])).collect();
        let tree = RegistryTree::build(leaves.clone());
        let root = tree.root();
        for (i, l) in leaves.iter().enumerate() {
            let path = tree.path(i);
            assert_eq!(path.len(), REGISTRY_DEPTH);
            assert!(verify_membership(l, &path, i as u32, &root), "leaf {i} failed");
        }
    }

    #[test]
    fn membership_rejects_wrong_root() {
        let leaves = vec![leaf(b"x"), leaf(b"y")];
        let tree = RegistryTree::build(leaves.clone());
        let mut bad = tree.root();
        bad[0] ^= 1;
        assert!(!verify_membership(&leaves[0], &tree.path(0), 0, &bad));
    }

    #[test]
    fn membership_rejects_corrupted_sibling() {
        let leaves = vec![leaf(b"x"), leaf(b"y")];
        let tree = RegistryTree::build(leaves.clone());
        let mut path = tree.path(0);
        path[0][0] ^= 1;
        assert!(!verify_membership(&leaves[0], &path, 0, &tree.root()));
    }

    #[test]
    fn membership_rejects_wrong_index() {
        let leaves = vec![leaf(b"x"), leaf(b"y"), leaf(b"z")];
        let tree = RegistryTree::build(leaves.clone());
        assert!(!verify_membership(&leaves[0], &tree.path(0), 1, &tree.root()));
    }

    #[test]
    fn membership_rejects_non_member() {
        let leaves = vec![leaf(b"x"), leaf(b"y")];
        let tree = RegistryTree::build(leaves);
        let outsider = leaf(b"forger");
        // No valid path for a leaf that isn't in the tree.
        assert!(!verify_membership(&outsider, &tree.path(0), 0, &tree.root()));
    }

    #[test]
    fn wrong_path_length_rejected() {
        let l = leaf(b"x");
        assert!(!verify_membership(&l, &[[0u8; 32]; 3], 0, &l));
    }

    #[test]
    fn leaf_index_above_depth_rejected() {
        let leaves = vec![leaf(b"x"), leaf(b"y")];
        let tree = RegistryTree::build(leaves.clone());
        // Same low bits as a valid index 0, but a high bit set beyond DEPTH.
        let bad_index = 1u32 << REGISTRY_DEPTH;
        assert!(!verify_membership(&leaves[0], &tree.path(0), bad_index, &tree.root()));
    }
}
