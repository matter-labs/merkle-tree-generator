use std::collections::HashMap;

use alloy_primitives::{Address, B256, U256, keccak256};
use anyhow::{Context, ensure};
use rs_merkle::{Hasher, MerkleTree};
use serde::{Deserialize, Serialize};

use crate::leaf::Leaf;

/// Keccak-256 hasher matching OpenZeppelin `MerkleProof`: pairs are sorted before hashing
/// and a lone node is promoted to the next level unchanged.
#[derive(Clone)]
struct SortedPairKeccak;

impl Hasher for SortedPairKeccak {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        keccak256(data).0
    }

    fn concat_and_hash(left: &[u8; 32], right: Option<&[u8; 32]>) -> [u8; 32] {
        let Some(right) = right else { return *left };
        let (a, b) = if left <= right {
            (left, right)
        } else {
            (right, left)
        };
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);
        Self::hash(&buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    pub claim_index: u64,
    pub account_address: Address,
    pub token_address: Address,
    #[serde(with = "crate::leaf::decimal_u256")]
    pub balance: U256,
    pub merkle_root: B256,
    pub merkle_path: Vec<B256>,
    pub leaf: B256,
}

pub struct ClaimTree {
    leaves: Vec<Leaf>,
    positions: HashMap<(Address, Address), usize>,
    tree: MerkleTree<SortedPairKeccak>,
}

impl ClaimTree {
    /// Leaves may come in any order but their `claim_index` values must be exactly `0..n`,
    /// and each `(account, token)` pair must appear once.
    pub fn new(mut leaves: Vec<Leaf>) -> anyhow::Result<Self> {
        ensure!(!leaves.is_empty(), "no leaves provided");
        leaves.sort_by_key(|leaf| leaf.claim_index);

        let mut positions = HashMap::with_capacity(leaves.len());
        for (position, leaf) in leaves.iter().enumerate() {
            ensure!(
                leaf.claim_index == position as u64,
                "claim_index values must be contiguous from zero, missing {position}"
            );
            let previous = positions.insert((leaf.account_address, leaf.token_address), position);
            ensure!(
                previous.is_none(),
                "duplicate leaf for account {} and token {}",
                leaf.account_address,
                leaf.token_address
            );
        }

        let hashes: Vec<[u8; 32]> = leaves.iter().map(|leaf| leaf.hash().0).collect();
        let tree = MerkleTree::from_leaves(&hashes);
        Ok(Self {
            leaves,
            positions,
            tree,
        })
    }

    pub fn root(&self) -> B256 {
        self.tree.root().expect("tree is non-empty").into()
    }

    pub fn proof(&self, account: Address, token: Address) -> anyhow::Result<Proof> {
        let position = *self
            .positions
            .get(&(account, token))
            .with_context(|| format!("no leaf for account {account} and token {token}"))?;
        let leaf = &self.leaves[position];
        Ok(Proof {
            claim_index: leaf.claim_index,
            account_address: leaf.account_address,
            token_address: leaf.token_address,
            balance: leaf.balance,
            merkle_root: self.root(),
            merkle_path: self
                .tree
                .proof(&[position])
                .proof_hashes()
                .iter()
                .copied()
                .map(B256::from)
                .collect(),
            leaf: leaf.hash(),
        })
    }
}

/// Same check as OpenZeppelin `MerkleProof.verify`.
pub fn verify_proof(leaf: B256, path: &[B256], root: B256) -> bool {
    let computed = path.iter().fold(leaf.0, |acc, sibling| {
        SortedPairKeccak::concat_and_hash(&acc, Some(&sibling.0))
    });
    computed == root.0
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, address, b256};

    use super::*;

    fn leaf(claim_index: u64, account: u64, token: u64, balance: u64) -> Leaf {
        Leaf {
            claim_index,
            account_address: Address::with_last_byte(account as u8),
            token_address: Address::with_last_byte(token as u8),
            balance: U256::from(balance),
        }
    }

    fn sample_leaves() -> Vec<Leaf> {
        vec![leaf(0, 1, 11, 10), leaf(1, 1, 12, 20), leaf(2, 2, 11, 30)]
    }

    #[test]
    fn hasher_sorts_pairs_and_promotes_lone_node() {
        let a = [0xff; 32];
        let b = [0x01; 32];
        assert_eq!(
            SortedPairKeccak::concat_and_hash(&a, Some(&b)),
            SortedPairKeccak::concat_and_hash(&b, Some(&a))
        );
        assert_eq!(SortedPairKeccak::concat_and_hash(&a, None), a);
    }

    #[test]
    fn leaf_hash_matches_abi_encode_packed() {
        let leaf = Leaf {
            claim_index: 7,
            account_address: address!("0x1111111111111111111111111111111111111111"),
            token_address: address!("0x2222222222222222222222222222222222222222"),
            balance: U256::from(1_000_000_000_000_000_000u64),
        };
        assert_eq!(
            leaf.hash(),
            b256!("0xc493f2b89fe2b066b4e202ffe33ced03e8cd5b2bb04337a10a41eb24e12a1068")
        );
    }

    #[test]
    fn root_matches_reference() {
        assert_eq!(
            ClaimTree::new(sample_leaves()).unwrap().root(),
            b256!("0x0ffb9b963d8a6f314f37b8ac7bb3f8610429ca7baa3de3b4edf578c03dc1b0be")
        );
    }

    #[test]
    fn proofs_verify_for_every_leaf() {
        for count in 1..=9 {
            let leaves: Vec<Leaf> = (0..count).map(|i| leaf(i, i, 100, i + 1)).collect();
            let tree = ClaimTree::new(leaves.clone()).unwrap();
            for leaf in &leaves {
                let proof = tree
                    .proof(leaf.account_address, leaf.token_address)
                    .unwrap();
                assert_eq!(proof.leaf, leaf.hash());
                assert!(verify_proof(proof.leaf, &proof.merkle_path, tree.root()));
            }
        }
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        let leaf = leaf(0, 1, 11, 10);
        let tree = ClaimTree::new(vec![leaf.clone()]).unwrap();
        assert_eq!(tree.root(), leaf.hash());
        assert!(
            tree.proof(leaf.account_address, leaf.token_address)
                .unwrap()
                .merkle_path
                .is_empty()
        );
    }

    #[test]
    fn input_order_does_not_change_root() {
        let mut shuffled = sample_leaves();
        shuffled.reverse();
        assert_eq!(
            ClaimTree::new(sample_leaves()).unwrap().root(),
            ClaimTree::new(shuffled).unwrap().root()
        );
    }

    #[test]
    fn tampered_proof_is_rejected() {
        let tree = ClaimTree::new(sample_leaves()).unwrap();
        let proof = tree
            .proof(Address::with_last_byte(1), Address::with_last_byte(12))
            .unwrap();
        let mut tampered = sample_leaves()[1].clone();
        tampered.balance += U256::from(1);
        assert!(!verify_proof(
            tampered.hash(),
            &proof.merkle_path,
            tree.root()
        ));
    }

    #[test]
    fn rejects_invalid_leaf_sets() {
        assert!(ClaimTree::new(vec![]).is_err());
        assert!(ClaimTree::new(vec![leaf(0, 1, 11, 10), leaf(2, 2, 11, 30)]).is_err());
        assert!(ClaimTree::new(vec![leaf(0, 1, 11, 10), leaf(1, 1, 11, 30)]).is_err());
    }

    #[test]
    fn missing_leaf_is_an_error() {
        let tree = ClaimTree::new(sample_leaves()).unwrap();
        assert!(
            tree.proof(Address::with_last_byte(9), Address::with_last_byte(11))
                .is_err()
        );
    }
}
