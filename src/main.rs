use std::path::PathBuf;

use alloy_primitives::Address;
use anyhow::Context;
use clap::{Parser, Subcommand};
use merkle_tree_generator::{ClaimTree, load_leaves_csv};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// CSV with columns `claim_index,account_address,token_address,balance`.
    #[arg(long, global = true, default_value = "leaves.csv")]
    leaves: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the Merkle root.
    Root,
    /// Print proofs for an account and one or more tokens as JSON.
    Proof {
        #[arg(long)]
        account: Address,
        #[arg(long, num_args = 1.., required = true)]
        tokens: Vec<Address>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let tree = ClaimTree::new(load_leaves_csv(&cli.leaves)?)?;

    match cli.command {
        Command::Root => println!("{}", tree.root()),
        Command::Proof { account, tokens } => {
            let proofs = tokens
                .into_iter()
                .map(|token| tree.proof(account, token))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let json =
                serde_json::to_string_pretty(&proofs).context("failed to serialize proofs")?;
            println!("{json}");
        }
    }
    Ok(())
}
