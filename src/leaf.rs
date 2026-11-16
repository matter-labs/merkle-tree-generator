use std::path::Path;

use alloy_primitives::{Address, B256, U256, keccak256};
use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    pub claim_index: u64,
    pub account_address: Address,
    pub token_address: Address,
    #[serde(with = "decimal_u256")]
    pub balance: U256,
}

impl Leaf {
    /// `keccak256(abi.encodePacked(uint256 index, address account, address token, uint256 amount))`.
    pub fn hash(&self) -> B256 {
        let mut encoded = [0u8; 32 + 20 + 20 + 32];
        encoded[..32].copy_from_slice(&U256::from(self.claim_index).to_be_bytes::<32>());
        encoded[32..52].copy_from_slice(self.account_address.as_slice());
        encoded[52..72].copy_from_slice(self.token_address.as_slice());
        encoded[72..].copy_from_slice(&self.balance.to_be_bytes::<32>());
        keccak256(encoded)
    }
}

/// Reads leaves from a CSV with columns `claim_index,account_address,token_address,balance`.
pub fn load_leaves_csv(path: impl AsRef<Path>) -> anyhow::Result<Vec<Leaf>> {
    let path = path.as_ref();
    let mut reader = csv::Reader::from_path(path)
        .with_context(|| format!("unable to open {}", path.display()))?;
    reader
        .deserialize()
        .enumerate()
        .map(|(row, leaf)| {
            leaf.with_context(|| format!("malformed row {} in {}", row + 1, path.display()))
        })
        .collect()
}

mod decimal_u256 {
    use alloy_primitives::U256;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
        let value = String::deserialize(deserializer)?;
        U256::from_str_radix(&value, 10).map_err(D::Error::custom)
    }
}
