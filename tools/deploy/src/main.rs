//! Post-deploy setup for the World ID Solana satellite program.
//!
//! Deploying the program (`anchor build` / `cargo build-sbf` + `solana program
//! deploy`) only uploads the executable — it does not create the `Config`
//! account or authorize any gateway. Run `initialize` once per deployment,
//! then `add-gateway` for each relay operator that should be allowed to push
//! bridged state. Driven by `scripts/deploy.sh`, which wraps this together
//! with the build/deploy/IDL steps into one entrypoint.
//!
//! Plain positional args, no argument-parsing crate — this is a small
//! internal tool run a handful of times per deployment, not a public CLI.
//!
//! # Usage
//!
//! ```bash
//! cargo run -p world-id-solana-deploy -- <rpc-url> <authority-keypair.json> initialize \
//!   [owner-pubkey] [root-validity-window] [tree-depth] [min-expiration-threshold]
//!
//! cargo run -p world-id-solana-deploy -- <rpc-url> <authority-keypair.json> add-gateway <gateway-pubkey>
//! cargo run -p world-id-solana-deploy -- <rpc-url> <authority-keypair.json> remove-gateway <gateway-pubkey>
//! cargo run -p world-id-solana-deploy -- <rpc-url> <authority-keypair.json> set-owner <new-owner-pubkey>
//! ```
//!
//! Set `PROGRAM_ID` in the environment to target a program id other than the
//! workspace default (`declare_id!` in `programs/world-id-solana/src/lib.rs`).

use std::{str::FromStr, sync::Arc};

use anchor_client::{
    Client, Cluster, Instruction, Program,
    anchor_lang::{InstructionData, ToAccountMetas, prelude::Pubkey, system_program},
};
use eyre::{Result, bail};
use solana_keypair::{Keypair, Signer, read_keypair_file};

const CONFIG_SEED: &[u8] = b"config";
const GATEWAY_SEED: &[u8] = b"gateway";

/// Real production `WorldIDSatellite` values (matching the deployed EVM
/// satellites' immutable constructor args) are used as `initialize`'s
/// defaults, so a Solana satellite bridging real World Chain state stays
/// semantically consistent with the other chains unless deliberately
/// overridden.
const DEFAULT_ROOT_VALIDITY_WINDOW: i64 = 3600;
const DEFAULT_TREE_DEPTH: u64 = 30;
const DEFAULT_MIN_EXPIRATION_THRESHOLD: i64 = 18_000;

fn anchor_instruction(
    program_id: Pubkey,
    accounts: impl ToAccountMetas,
    args: impl InstructionData,
) -> Instruction {
    Instruction {
        program_id,
        accounts: accounts.to_account_metas(None),
        data: args.data(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: world-id-solana-deploy <rpc-url> <authority-keypair.json> <command> [args...]

commands:
  initialize [owner] [root-validity-window] [tree-depth] [min-expiration-threshold]
  add-gateway <gateway-pubkey>
  remove-gateway <gateway-pubkey>
  set-owner <new-owner-pubkey>

env:
  PROGRAM_ID  override the target program id (default: the workspace satellite program id)"
    );
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        usage();
    }
    let rpc_url = &args[1];
    let authority_keypair_path = &args[2];
    let command = args[3].as_str();
    let rest = &args[4..];

    let authority = read_keypair_file(authority_keypair_path).map_err(|e| {
        eyre::eyre!("failed to read authority keypair {authority_keypair_path}: {e}")
    })?;
    let authority_pubkey = authority.pubkey();

    let program_id = match std::env::var("PROGRAM_ID") {
        Ok(id) => Pubkey::from_str(&id)?,
        Err(_) => world_id_solana::ID,
    };

    let cluster = Cluster::from_str(rpc_url).map_err(|e| eyre::eyre!("invalid RPC URL: {e}"))?;
    let client = Client::new(cluster, Arc::new(authority));
    let program: Program<Arc<Keypair>> = client.program(program_id)?;

    let (config, _) = Pubkey::find_program_address(&[CONFIG_SEED], &program_id);

    match command {
        "initialize" => {
            let owner_pubkey = match rest.first() {
                Some(o) => Pubkey::from_str(o)?,
                None => authority_pubkey,
            };
            let root_validity_window = rest
                .get(1)
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(DEFAULT_ROOT_VALIDITY_WINDOW);
            let tree_depth = rest
                .get(2)
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(DEFAULT_TREE_DEPTH);
            let min_expiration_threshold = rest
                .get(3)
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(DEFAULT_MIN_EXPIRATION_THRESHOLD);

            let ix = anchor_instruction(
                program_id,
                world_id_solana::accounts::Initialize {
                    config,
                    payer: authority_pubkey,
                    system_program: system_program::ID,
                },
                world_id_solana::instruction::Initialize {
                    owner: owner_pubkey,
                    root_validity_window,
                    tree_depth,
                    min_expiration_threshold,
                },
            );
            let sig = program.request().instruction(ix).send().await?;
            println!(
                "initialize: config={config} owner={owner_pubkey} \
                 root_validity_window={root_validity_window} tree_depth={tree_depth} \
                 min_expiration_threshold={min_expiration_threshold} tx={sig}"
            );
        }
        "add-gateway" => {
            let Some(gateway) = rest.first() else {
                bail!("add-gateway requires a <gateway-pubkey> argument");
            };
            let gateway_pubkey = Pubkey::from_str(gateway)?;
            let (gateway_authorization, _) =
                Pubkey::find_program_address(&[GATEWAY_SEED, gateway_pubkey.as_ref()], &program_id);

            let ix = anchor_instruction(
                program_id,
                world_id_solana::accounts::AddGateway {
                    config,
                    owner: authority_pubkey,
                    gateway_authorization,
                    system_program: system_program::ID,
                },
                world_id_solana::instruction::AddGateway {
                    gateway: gateway_pubkey,
                },
            );
            let sig = program.request().instruction(ix).send().await?;
            println!(
                "add_gateway: gateway={gateway_pubkey} authorization={gateway_authorization} tx={sig}"
            );
        }
        "remove-gateway" => {
            let Some(gateway) = rest.first() else {
                bail!("remove-gateway requires a <gateway-pubkey> argument");
            };
            let gateway_pubkey = Pubkey::from_str(gateway)?;
            let (gateway_authorization, _) =
                Pubkey::find_program_address(&[GATEWAY_SEED, gateway_pubkey.as_ref()], &program_id);

            let ix = anchor_instruction(
                program_id,
                world_id_solana::accounts::RemoveGateway {
                    config,
                    owner: authority_pubkey,
                    gateway_authorization,
                },
                world_id_solana::instruction::RemoveGateway {},
            );
            let sig = program.request().instruction(ix).send().await?;
            println!("remove_gateway: gateway={gateway_pubkey} tx={sig}");
        }
        "set-owner" => {
            let Some(new_owner) = rest.first() else {
                bail!("set-owner requires a <new-owner-pubkey> argument");
            };
            let new_owner_pubkey = Pubkey::from_str(new_owner)?;

            let ix = anchor_instruction(
                program_id,
                world_id_solana::accounts::SetOwner {
                    config,
                    owner: authority_pubkey,
                },
                world_id_solana::instruction::SetOwner {
                    new_owner: new_owner_pubkey,
                },
            );
            let sig = program.request().instruction(ix).send().await?;
            println!("set_owner: new_owner={new_owner_pubkey} tx={sig}");
        }
        _ => usage(),
    }

    Ok(())
}
