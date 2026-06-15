//! v2-A DKIM key registry (host side). Builds the Poseidon Merkle tree of
//! known-good `(domain, selector, pubkey)` entries and resolves a prover's
//! authentication path. The verifier pins the resulting `root`; the guest
//! proves the witnessed key is a member of it. See v2-A design §6.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use nce_core::registry::{registry_leaf, RegistryTree, REGISTRY_DEPTH};

use crate::dns;

/// On-disk registry. Entries are stored in leaf-sorted order; `index` is the
/// leaf's position in the tree and `path` its authentication path.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryFile {
    pub depth: usize,
    pub root: String, // hex
    pub entries: Vec<RegistryEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub domain: String,
    pub selector: String,
    pub n: String, // hex, modulus big-endian
    pub e: String, // hex, exponent big-endian
    pub index: u32,
    pub path: Vec<String>, // hex siblings, leaf->root
}

/// A prover's resolved membership material for a `(domain, selector)`.
pub struct Resolved {
    pub pubkey_n: Vec<u8>,
    pub pubkey_e: Vec<u8>,
    pub merkle_path: Vec<[u8; 32]>,
    pub leaf_index: u32,
    pub root: [u8; 32],
}

impl RegistryFile {
    /// Build from raw keys: each `(domain, selector, n, e)`. Leaves are sorted
    /// by leaf value for determinism; the index is the sorted position.
    pub fn build(mut keys: Vec<(String, String, Vec<u8>, Vec<u8>)>) -> Self {
        // (leaf, domain, selector, n, e), sorted by leaf.
        let mut rows: Vec<([u8; 32], String, String, Vec<u8>, Vec<u8>)> = keys
            .drain(..)
            .map(|(d, s, n, e)| {
                let leaf = registry_leaf(d.as_bytes(), s.as_bytes(), &n, &e);
                (leaf, d, s, n, e)
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));

        let leaves: Vec<[u8; 32]> = rows.iter().map(|r| r.0).collect();
        let tree = RegistryTree::build(leaves);
        let entries = rows
            .iter()
            .enumerate()
            .map(|(i, (_, d, s, n, e))| RegistryEntry {
                domain: d.clone(),
                selector: s.clone(),
                n: hex::encode(n),
                e: hex::encode(e),
                index: i as u32,
                path: tree.path(i).iter().map(hex::encode).collect(),
            })
            .collect();

        RegistryFile {
            depth: REGISTRY_DEPTH,
            root: hex::encode(tree.root()),
            entries,
        }
    }

    /// One-entry registry from a DKIM TXT tag — the offline/test/air-gapped
    /// path. The prover effectively vouches for their own key; security comes
    /// from the verifier pinning the resulting root.
    pub fn build_from_tag(domain: &str, selector: &str, tag: &str) -> Result<Self> {
        let pk = dns::parse_dkim_tag(tag)?;
        Ok(Self::build(vec![(domain.to_string(), selector.to_string(), pk.n, pk.e)]))
    }

    /// One-entry registry from a live DNS lookup.
    pub fn build_from_dns(domain: &str, selector: &str) -> Result<Self> {
        let pk = dns::lookup(domain.as_bytes(), selector.as_bytes())?;
        Ok(Self::build(vec![(domain.to_string(), selector.to_string(), pk.n, pk.e)]))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("reading registry {}", path.display()))?;
        serde_json::from_str(&s).context("parsing registry JSON")
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self).context("serializing registry")?;
        std::fs::write(path, s).with_context(|| format!("writing registry {}", path.display()))?;
        Ok(())
    }

    pub fn root_bytes(&self) -> Result<[u8; 32]> {
        decode_32(&self.root)
    }

    /// Resolve the membership material for a prover's `(domain, selector)`.
    pub fn resolve(&self, domain: &str, selector: &str) -> Result<Resolved> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.domain == domain && e.selector == selector)
            .ok_or_else(|| {
                anyhow!("no registry entry for {selector}._domainkey.{domain}")
            })?;
        let mut path = Vec::with_capacity(entry.path.len());
        for h in &entry.path {
            path.push(decode_32(h)?);
        }
        Ok(Resolved {
            pubkey_n: hex::decode(&entry.n).context("entry n not hex")?,
            pubkey_e: hex::decode(&entry.e).context("entry e not hex")?,
            merkle_path: path,
            leaf_index: entry.index,
            root: self.root_bytes()?,
        })
    }
}

fn decode_32(h: &str) -> Result<[u8; 32]> {
    let v = hex::decode(h).context("hex decode")?;
    let arr: [u8; 32] = v
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes, got {}", v.len()))?;
    Ok(arr)
}
