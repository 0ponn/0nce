//! v2-A registry leaf + Poseidon Merkle membership.
//!
//! Shared by the guest (which proves a witnessed DKIM key is a registry
//! member) and the host (which builds the tree). Same primitive as the
//! nullifier: `light-poseidon` over BN254, Circom/Iden3 params, with each
//! variable-length input compressed to one field element via SHA-256 then
//! reduced mod the field order. Each input occupies its own Poseidon lane,
//! so there is no concatenation ambiguity.
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

/// A 32-byte node value (the BE encoding of a field element, as produced by
/// `fr_to_bytes`) back into a field element. Lossless: node values are always
/// valid field elements < the field order.
fn fr_from_bytes(b: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
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

/// 2-to-1 compression `node = Poseidon(left, right)`.
pub fn poseidon2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("poseidon init t=3");
    fr_to_bytes(
        h.hash(&[fr_from_bytes(left), fr_from_bytes(right)])
            .expect("poseidon hash (node)"),
    )
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
    let mut node = *leaf;
    for (level, sibling) in path.iter().enumerate() {
        node = if (leaf_index >> level) & 1 == 0 {
            poseidon2(&node, sibling)
        } else {
            poseidon2(sibling, &node)
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
            empties.push(poseidon2(&e, &e));
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
                next.push(poseidon2(&left, &right));
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
}
