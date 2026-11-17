# merkle-tree-generator

Builds a Keccak-256 Merkle tree over claim leaves and produces the root and inclusion proofs. Proofs verify with
OpenZeppelin `MerkleProof.verify` (sorted-pair hashing).

## Leaf format

CSV with header `claim_index,account_address,token_address,balance`:

```csv
claim_index,account_address,token_address,balance
0,0x0000000000000000000000000000000000000001,0x000000000000000000000000000000000000000b,10
```

- `claim_index` values must be exactly `0..n` (any row order); the index is the leaf position in the tree.
- `balance` is a decimal `uint256`.
- Each `(account_address, token_address)` pair must be unique.

Leaf hash: `keccak256(abi.encodePacked(uint256 claim_index, address account, address token, uint256 balance))`.

## Usage

```bash
cargo run --release -- root --leaves leaves.csv
cargo run --release -- proof --leaves leaves.csv --account <ADDRESS> --tokens <TOKEN> [<TOKEN> ...]
```

`proof` prints a JSON array with one entry per token:

```json
{
  "claimIndex": 0,
  "accountAddress": "0x…",
  "tokenAddress": "0x…",
  "balance": "10",
  "merkleRoot": "0x…",
  "merklePath": ["0x…"],
  "leaf": "0x…"
}
```

## Library

```rust
let tree = merkle_tree_generator::ClaimTree::new(merkle_tree_generator::load_leaves_csv("leaves.csv")?)?;
let proof = tree.proof(account, token)?;
assert!(merkle_tree_generator::verify_proof(proof.leaf, &proof.merkle_path, tree.root()));
```

## Tests

`tests/mainnet.rs` checks real proofs from the ZKsync Lite exit tree against the `MERKLE_ROOT` of the mainnet claim
distributor `0x0a14b696350546110a0d8acdb86226983af9d2a0`. Rebuilding the full tree (16.6M leaves) is ignored by default:

```bash
MAINNET_LEAVES_CSV=new_leaves.csv cargo test --release -- --ignored
```
