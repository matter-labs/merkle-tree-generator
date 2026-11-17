//! Real ZKsync Lite exit tree: 16,619,318 leaves, root stored as `MERKLE_ROOT` of the claim
//! distributor `0x0a14b696350546110a0d8acdb86226983af9d2a0` on Ethereum mainnet.

use alloy_primitives::{B256, U256, b256};
use merkle_tree_generator::{ClaimTree, Leaf, Proof, load_leaves_csv, verify_proof};

const MAINNET_ROOT: B256 =
    b256!("0x7b4a44a4f8e14f03efcd4fe625b29755eb275f8621e69167fcd152c86ab37141");

const MAINNET_LEAF_COUNT: usize = 16_619_318;

fn fixture_proofs() -> Vec<Proof> {
    serde_json::from_str(include_str!("data/mainnet_proofs.json")).unwrap()
}

fn leaf_of(proof: &Proof) -> Leaf {
    Leaf {
        claim_index: proof.claim_index,
        account_address: proof.account_address,
        token_address: proof.token_address,
        balance: proof.balance,
    }
}

#[test]
fn mainnet_proofs_verify_against_onchain_root() {
    for proof in fixture_proofs() {
        let leaf = leaf_of(&proof);
        assert_eq!(proof.merkle_root, MAINNET_ROOT);
        assert_eq!(leaf.hash(), proof.leaf, "claim_index {}", proof.claim_index);
        assert!(
            verify_proof(leaf.hash(), &proof.merkle_path, MAINNET_ROOT),
            "claim_index {}",
            proof.claim_index
        );

        let tampered = Leaf {
            balance: leaf.balance + U256::from(1),
            ..leaf
        };
        assert!(!verify_proof(
            tampered.hash(),
            &proof.merkle_path,
            MAINNET_ROOT
        ));
    }
}

/// Needs the full leaves CSV (~1.8 GB), e.g. `new_leaves.csv` from `exit_tree_generator create-new-leaves`
/// run on the official snapshot: `MAINNET_LEAVES_CSV=new_leaves.csv cargo test --release -- --ignored`.
#[test]
#[ignore = "requires MAINNET_LEAVES_CSV with the full mainnet leaves"]
fn mainnet_tree_matches_onchain_root() {
    let path = std::env::var("MAINNET_LEAVES_CSV").expect("MAINNET_LEAVES_CSV is not set");
    let leaves = load_leaves_csv(path).unwrap();
    assert_eq!(leaves.len(), MAINNET_LEAF_COUNT);

    let tree = ClaimTree::new(leaves).unwrap();
    assert_eq!(tree.root(), MAINNET_ROOT);

    for expected in fixture_proofs() {
        let proof = tree
            .proof(expected.account_address, expected.token_address)
            .unwrap();
        assert_eq!(proof, expected);
    }
}
