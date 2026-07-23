#![allow(unexpected_cfgs)]

//! Anchor-based Solana satellite for World ID.
//!
//! The program bridges World ID state (roots, issuer keys, OPRF keys) into
//! Solana accounts on behalf of one or more authorized gateway signers, and
//! verifies Groth16 uniqueness/session proofs against that bridged state.
//!
//! State-mutating instructions (`update_root`, `set_issuer_pubkey`,
//! `set_oprf_key`) each fold their own commitment into a running keccak hash
//! chain (`Config::latest_chain_head`), mirroring
//! `StateBridge._applyAndCommit`/`Lib.commitChained` on the EVM side: the new
//! head is `keccak256(prior_head || block_hash || abi_encoded_call)`, computed
//! on-chain from the instruction's own arguments rather than accepted as an
//! opaque value from the gateway. This gives the same tamper-evidence
//! property the EVM satellite gets from recomputing `hashChained` before
//! applying commits.

use anchor_lang::prelude::*;

pub mod verifier;

use verifier::{SolanaCompressedProof, verify_solana_compressed_proof};

declare_id!("BxHvVSWUkStm7RsKySrzyGWV85PNF8TsGTsPEQ3PsVfK");

const CONFIG_SEED: &[u8] = b"config";
const ROOT_SEED: &[u8] = b"root";
const ISSUER_SEED: &[u8] = b"issuer";
const OPRF_SEED: &[u8] = b"oprf";
const GATEWAY_SEED: &[u8] = b"gateway";

/// `bytes4(keccak256("updateRoot(uint256,uint256,bytes32)"))`, matching
/// `StateBridge._UPDATE_ROOT_SELECTOR`.
const UPDATE_ROOT_SELECTOR: [u8; 4] = [0xb2, 0xa8, 0x10, 0xa9];
/// `bytes4(keccak256("setIssuerPubkey(uint64,uint256,uint256,bytes32)"))`,
/// matching `StateBridge._SET_ISSUER_PUBKEY_SELECTOR`.
const SET_ISSUER_PUBKEY_SELECTOR: [u8; 4] = [0xcb, 0x2b, 0x90, 0x34];
/// `bytes4(keccak256("setOprfKey(uint160,uint256,uint256,bytes32)"))`,
/// matching `StateBridge._SET_OPRF_KEY_SELECTOR`.
const SET_OPRF_KEY_SELECTOR: [u8; 4] = [0xb3, 0x8c, 0xfd, 0xa7];

/// World ID Solana satellite program.
#[program]
pub mod world_id_solana_satellite {
    use super::*;

    /// Initializes satellite configuration. Callable once.
    pub fn initialize(
        ctx: Context<Initialize>,
        owner: Pubkey,
        root_validity_window: i64,
        tree_depth: u64,
        min_expiration_threshold: i64,
    ) -> Result<()> {
        require!(owner != Pubkey::default(), SatelliteError::ZeroPubkey);
        require!(
            root_validity_window > 0,
            SatelliteError::InvalidRootValidityWindow
        );
        require!(tree_depth > 0, SatelliteError::InvalidTreeDepth);
        require!(
            min_expiration_threshold > 0,
            SatelliteError::InvalidMinExpirationThreshold
        );

        let config = &mut ctx.accounts.config;
        config.owner = owner;
        config.root_validity_window = root_validity_window;
        config.tree_depth = tree_depth;
        config.min_expiration_threshold = min_expiration_threshold;
        config.latest_root = [0u8; 32];
        config.latest_chain_head = [0u8; 32];
        config.bump = ctx.bumps.config;

        Ok(())
    }

    /// Transfers satellite ownership. Owner-signed.
    pub fn set_owner(ctx: Context<SetOwner>, new_owner: Pubkey) -> Result<()> {
        require!(new_owner != Pubkey::default(), SatelliteError::ZeroPubkey);
        ctx.accounts.config.owner = new_owner;
        Ok(())
    }

    /// Authorizes a new gateway signer. Owner-signed. Multiple gateways may
    /// be authorized concurrently, mirroring `StateBridge._addGateway`.
    pub fn add_gateway(ctx: Context<AddGateway>, gateway: Pubkey) -> Result<()> {
        require!(gateway != Pubkey::default(), SatelliteError::ZeroPubkey);

        let auth = &mut ctx.accounts.gateway_authorization;
        auth.config = ctx.accounts.config.key();
        auth.gateway = gateway;
        auth.bump = ctx.bumps.gateway_authorization;

        Ok(())
    }

    /// Revokes a gateway signer's authorization. Owner-signed. Closing the
    /// account (rather than flipping a flag) means a revoked gateway has no
    /// bridged authorization state left to reason about.
    pub fn remove_gateway(_ctx: Context<RemoveGateway>) -> Result<()> {
        Ok(())
    }

    /// Records a bridged World ID Merkle root and folds the commitment into
    /// the satellite's keccak chain head.
    pub fn update_root(
        ctx: Context<GatewayUpdateRoot>,
        root: [u8; 32],
        timestamp: i64,
        proof_id: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<()> {
        require!(root != [0u8; 32], SatelliteError::InvalidRoot);
        require!(timestamp > 0, SatelliteError::InvalidTimestamp);

        let config_key = ctx.accounts.config.key();
        let timestamp_word = i64_word(timestamp)?;
        let new_head = chain_head_after_commit(
            &ctx.accounts.config.latest_chain_head,
            &block_hash,
            &UPDATE_ROOT_SELECTOR,
            &[&root, &timestamp_word, &proof_id],
        );

        let config = &mut ctx.accounts.config;
        config.latest_root = root;
        config.latest_chain_head = new_head;

        let state = &mut ctx.accounts.root_state;
        state.config = config_key;
        state.root = root;
        state.timestamp = timestamp;
        state.proof_id = proof_id;
        state.bump = ctx.bumps.root_state;

        Ok(())
    }

    /// Records a bridged credential issuer public key and folds the
    /// commitment into the satellite's keccak chain head.
    pub fn set_issuer_pubkey(
        ctx: Context<GatewaySetIssuerPubkey>,
        issuer_schema_id: u64,
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<()> {
        require!(
            !is_zero_point(&x, &y),
            SatelliteError::UnregisteredIssuerSchemaId
        );

        let config_key = ctx.accounts.config.key();
        let issuer_word = u64_word(issuer_schema_id);
        let new_head = chain_head_after_commit(
            &ctx.accounts.config.latest_chain_head,
            &block_hash,
            &SET_ISSUER_PUBKEY_SELECTOR,
            &[&issuer_word, &x, &y, &proof_id],
        );
        ctx.accounts.config.latest_chain_head = new_head;

        let state = &mut ctx.accounts.issuer_state;
        state.config = config_key;
        state.key = key20_from_u64(issuer_schema_id);
        state.x = x;
        state.y = y;
        state.proof_id = proof_id;
        state.bump = ctx.bumps.issuer_state;

        Ok(())
    }

    /// Records a bridged OPRF public key and folds the commitment into the
    /// satellite's keccak chain head. `rp_id` is the full 160-bit OPRF key id
    /// (matching `StateBridge.oprfKeyIdToPubkeyAndProofId`'s `uint160`
    /// keyspace), independent of the 64-bit `rpId` accepted by `verify`.
    pub fn set_oprf_key(
        ctx: Context<GatewaySetOprfKey>,
        rp_id: [u8; 20],
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<()> {
        require!(
            !is_zero_point(&x, &y),
            SatelliteError::UnregisteredOprfKeyId
        );

        let config_key = ctx.accounts.config.key();
        let rp_word = word20(&rp_id);
        let new_head = chain_head_after_commit(
            &ctx.accounts.config.latest_chain_head,
            &block_hash,
            &SET_OPRF_KEY_SELECTOR,
            &[&rp_word, &x, &y, &proof_id],
        );
        ctx.accounts.config.latest_chain_head = new_head;

        let state = &mut ctx.accounts.oprf_state;
        state.config = config_key;
        state.key = rp_id;
        state.x = x;
        state.y = y;
        state.proof_id = proof_id;
        state.bump = ctx.bumps.oprf_state;

        Ok(())
    }

    /// Verifies a uniqueness proof against bridged satellite state.
    pub fn verify(ctx: Context<Verify>, args: VerifyArgs) -> Result<()> {
        verify_proof_and_signals(
            &ctx.accounts.config,
            &ctx.accounts.root_state,
            &ctx.accounts.issuer_state,
            &ctx.accounts.oprf_state,
            args,
        )
    }

    /// Verifies a session proof against bridged satellite state.
    pub fn verify_session(ctx: Context<VerifySession>, args: VerifySessionArgs) -> Result<()> {
        verify_proof_and_signals(
            &ctx.accounts.config,
            &ctx.accounts.root_state,
            &ctx.accounts.issuer_state,
            &ctx.accounts.oprf_state,
            VerifyArgs {
                nullifier: args.session_nullifier[0],
                action: args.session_nullifier[1],
                rp_id: args.rp_id,
                nonce: args.nonce,
                signal_hash: args.signal_hash,
                expires_at_min: args.expires_at_min,
                issuer_schema_id: args.issuer_schema_id,
                credential_genesis_issued_at_min: args.credential_genesis_issued_at_min,
                session_id: args.session_id,
                proof: args.proof,
            },
        )
    }
}

fn verify_proof_and_signals(
    config: &Config,
    root_state: &RootState,
    issuer_state: &PubkeyState,
    oprf_state: &PubkeyState,
    args: VerifyArgs,
) -> Result<()> {
    require!(
        is_valid_root(config, root_state)?,
        SatelliteError::InvalidMerkleRoot
    );
    require!(
        !is_zero_point(&issuer_state.x, &issuer_state.y),
        SatelliteError::UnregisteredIssuerSchemaId
    );
    require!(
        !is_zero_point(&oprf_state.x, &oprf_state.y),
        SatelliteError::UnregisteredOprfKeyId
    );

    let now = Clock::get()?.unix_timestamp;
    require!(
        args.expires_at_min >= now - config.min_expiration_threshold,
        SatelliteError::ExpirationTooOld
    );

    let public_inputs = [
        args.nullifier,
        u64_word(args.issuer_schema_id),
        issuer_state.x,
        issuer_state.y,
        i64_word(args.expires_at_min)?,
        args.credential_genesis_issued_at_min,
        args.proof.root,
        u64_word(config.tree_depth),
        u64_word(args.rp_id),
        args.action,
        oprf_state.x,
        oprf_state.y,
        args.signal_hash,
        args.nonce,
        args.session_id,
    ];

    verify_solana_compressed_proof(&args.proof.into(), &public_inputs)
        .map_err(|_| error!(SatelliteError::ProofInvalid))
}

fn is_valid_root(config: &Config, root_state: &RootState) -> Result<bool> {
    if root_state.timestamp == 0 {
        return Ok(false);
    }
    if root_state.root == config.latest_root {
        return Ok(true);
    }

    let now = Clock::get()?.unix_timestamp;
    let expires_at = root_state
        .timestamp
        .checked_add(config.root_validity_window)
        .ok_or_else(|| error!(SatelliteError::InvalidTimestamp))?;
    Ok(now <= expires_at)
}

fn is_zero_point(x: &[u8; 32], y: &[u8; 32]) -> bool {
    *x == [0u8; 32] && *y == [0u8; 32]
}

/// Folds a single commitment into the running keccak chain head:
/// `keccak256(prior_head || block_hash || selector || words...)`, matching
/// `Lib.commitChained`'s `keccak256(abi.encodePacked(head, blockHash, data))`
/// where `data` is `abi.encodeWithSelector(selector, words...)` for commits
/// whose ABI-encoded arguments are all static (32-byte-word) types, as is the
/// case for `updateRoot`/`setIssuerPubkey`/`setOprfKey`.
fn chain_head_after_commit(
    prior_head: &[u8; 32],
    block_hash: &[u8; 32],
    selector: &[u8; 4],
    words: &[&[u8; 32]],
) -> [u8; 32] {
    let mut data = Vec::with_capacity(4 + words.len() * 32);
    data.extend_from_slice(selector);
    for word in words {
        data.extend_from_slice(word.as_slice());
    }

    solana_keccak_hasher::hashv(&[prior_head.as_slice(), block_hash.as_slice(), &data]).to_bytes()
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn i64_word(value: i64) -> Result<[u8; 32]> {
    require!(value >= 0, SatelliteError::InvalidTimestamp);
    Ok(u64_word(value as u64))
}

/// Zero-extends a `u64` into a big-endian 20-byte (160-bit) key, matching
/// Solidity's `uint160(uint64)` upcast used to look up
/// `oprfKeyIdToPubkeyAndProofId` from `verify`'s 64-bit `rpId`.
fn key20_from_u64(value: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[12..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Left-pads a 160-bit key into a big-endian 32-byte field word, matching the
/// ABI encoding of a `uint160` value.
fn word20(value: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(value);
    out
}

/// Initialize accounts.
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Satellite configuration PDA.
    #[account(init, payer = payer, space = Config::SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    /// Account funding initialization.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Owner-rotation accounts.
#[derive(Accounts)]
pub struct SetOwner<'info> {
    /// Satellite configuration PDA.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = owner)]
    pub config: Account<'info, Config>,
    /// Current satellite owner.
    pub owner: Signer<'info>,
}

/// Gateway-authorization accounts.
#[derive(Accounts)]
#[instruction(gateway: Pubkey)]
pub struct AddGateway<'info> {
    /// Satellite configuration PDA.
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = owner)]
    pub config: Account<'info, Config>,
    /// Satellite owner.
    #[account(mut)]
    pub owner: Signer<'info>,
    /// Per-gateway authorization PDA.
    #[account(
        init,
        payer = owner,
        space = GatewayAuthorization::SPACE,
        seeds = [GATEWAY_SEED, gateway.as_ref()],
        bump
    )]
    pub gateway_authorization: Account<'info, GatewayAuthorization>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Gateway-revocation accounts.
#[derive(Accounts)]
pub struct RemoveGateway<'info> {
    /// Satellite configuration PDA.
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = owner)]
    pub config: Account<'info, Config>,
    /// Satellite owner; receives the closed account's rent.
    #[account(mut)]
    pub owner: Signer<'info>,
    /// Per-gateway authorization PDA being revoked.
    #[account(
        mut,
        close = owner,
        seeds = [GATEWAY_SEED, gateway_authorization.gateway.as_ref()],
        bump = gateway_authorization.bump,
        constraint = gateway_authorization.config == config.key() @ SatelliteError::InvalidStateAccount
    )]
    pub gateway_authorization: Account<'info, GatewayAuthorization>,
}

/// Gateway root update accounts.
#[derive(Accounts)]
#[instruction(root: [u8; 32])]
pub struct GatewayUpdateRoot<'info> {
    /// Satellite configuration PDA.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Authorized gateway signer.
    #[account(mut)]
    pub gateway: Signer<'info>,
    /// This gateway's authorization PDA.
    #[account(
        seeds = [GATEWAY_SEED, gateway.key().as_ref()],
        bump = gateway_authorization.bump,
        constraint = gateway_authorization.config == config.key() @ SatelliteError::UnauthorizedGateway
    )]
    pub gateway_authorization: Account<'info, GatewayAuthorization>,
    /// Root state PDA.
    #[account(
        init_if_needed,
        payer = gateway,
        space = RootState::SPACE,
        seeds = [ROOT_SEED, root.as_ref()],
        bump
    )]
    pub root_state: Account<'info, RootState>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Gateway issuer key update accounts.
#[derive(Accounts)]
#[instruction(issuer_schema_id: u64)]
pub struct GatewaySetIssuerPubkey<'info> {
    /// Satellite configuration PDA.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Authorized gateway signer.
    #[account(mut)]
    pub gateway: Signer<'info>,
    /// This gateway's authorization PDA.
    #[account(
        seeds = [GATEWAY_SEED, gateway.key().as_ref()],
        bump = gateway_authorization.bump,
        constraint = gateway_authorization.config == config.key() @ SatelliteError::UnauthorizedGateway
    )]
    pub gateway_authorization: Account<'info, GatewayAuthorization>,
    /// Issuer public key state PDA.
    #[account(
        init_if_needed,
        payer = gateway,
        space = PubkeyState::SPACE,
        seeds = [ISSUER_SEED, &key20_from_u64(issuer_schema_id)],
        bump
    )]
    pub issuer_state: Account<'info, PubkeyState>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Gateway OPRF key update accounts.
#[derive(Accounts)]
#[instruction(rp_id: [u8; 20])]
pub struct GatewaySetOprfKey<'info> {
    /// Satellite configuration PDA.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Authorized gateway signer.
    #[account(mut)]
    pub gateway: Signer<'info>,
    /// This gateway's authorization PDA.
    #[account(
        seeds = [GATEWAY_SEED, gateway.key().as_ref()],
        bump = gateway_authorization.bump,
        constraint = gateway_authorization.config == config.key() @ SatelliteError::UnauthorizedGateway
    )]
    pub gateway_authorization: Account<'info, GatewayAuthorization>,
    /// OPRF public key state PDA.
    #[account(
        init_if_needed,
        payer = gateway,
        space = PubkeyState::SPACE,
        seeds = [OPRF_SEED, rp_id.as_ref()],
        bump
    )]
    pub oprf_state: Account<'info, PubkeyState>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Uniqueness-proof verification accounts. PDA seeds are derived from `args`,
/// so an invalid root/issuer/OPRF state account fails Anchor's own account
/// deserialization rather than relying on a handler-body check.
#[derive(Accounts)]
#[instruction(args: VerifyArgs)]
pub struct Verify<'info> {
    /// Satellite configuration PDA.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Root state account for the proof root.
    #[account(
        seeds = [ROOT_SEED, args.proof.root.as_ref()],
        bump = root_state.bump,
        constraint = root_state.config == config.key() @ SatelliteError::InvalidStateAccount
    )]
    pub root_state: Account<'info, RootState>,
    /// Issuer public key state account.
    #[account(
        seeds = [ISSUER_SEED, &key20_from_u64(args.issuer_schema_id)],
        bump = issuer_state.bump,
        constraint = issuer_state.config == config.key() @ SatelliteError::InvalidStateAccount
    )]
    pub issuer_state: Account<'info, PubkeyState>,
    /// OPRF public key state account.
    #[account(
        seeds = [OPRF_SEED, &key20_from_u64(args.rp_id)],
        bump = oprf_state.bump,
        constraint = oprf_state.config == config.key() @ SatelliteError::InvalidStateAccount
    )]
    pub oprf_state: Account<'info, PubkeyState>,
}

/// Session-proof verification accounts. See [`Verify`]; kept as a separate
/// type because Anchor's per-instruction `#[instruction(..)]` seeds binding
/// requires a concrete args type, and `verify`/`verify_session` take
/// different ones.
#[derive(Accounts)]
#[instruction(args: VerifySessionArgs)]
pub struct VerifySession<'info> {
    /// Satellite configuration PDA.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Root state account for the proof root.
    #[account(
        seeds = [ROOT_SEED, args.proof.root.as_ref()],
        bump = root_state.bump,
        constraint = root_state.config == config.key() @ SatelliteError::InvalidStateAccount
    )]
    pub root_state: Account<'info, RootState>,
    /// Issuer public key state account.
    #[account(
        seeds = [ISSUER_SEED, &key20_from_u64(args.issuer_schema_id)],
        bump = issuer_state.bump,
        constraint = issuer_state.config == config.key() @ SatelliteError::InvalidStateAccount
    )]
    pub issuer_state: Account<'info, PubkeyState>,
    /// OPRF public key state account.
    #[account(
        seeds = [OPRF_SEED, &key20_from_u64(args.rp_id)],
        bump = oprf_state.bump,
        constraint = oprf_state.config == config.key() @ SatelliteError::InvalidStateAccount
    )]
    pub oprf_state: Account<'info, PubkeyState>,
}

/// Satellite configuration.
#[account]
pub struct Config {
    /// Satellite owner.
    pub owner: Pubkey,
    /// Historic root validity window in seconds.
    pub root_validity_window: i64,
    /// World ID tree depth.
    pub tree_depth: u64,
    /// Minimum acceptable expiration age in seconds.
    pub min_expiration_threshold: i64,
    /// Latest bridged root.
    pub latest_root: [u8; 32],
    /// Latest bridged World Chain keccak chain head, folded in by
    /// `update_root`/`set_issuer_pubkey`/`set_oprf_key`.
    pub latest_chain_head: [u8; 32],
    /// Config PDA bump.
    pub bump: u8,
}

impl Config {
    /// Serialized account size.
    pub const SPACE: usize = 8 + 32 + 8 + 8 + 8 + 32 + 32 + 1;
}

/// Per-gateway authorization state. Existence of this PDA (seeded by the
/// gateway's pubkey) is the sole authorization check for gateway-facing
/// instructions, mirroring `StateBridge.authorizedGateways`'s allowlist.
#[account]
pub struct GatewayAuthorization {
    /// Config account this authorization belongs to.
    pub config: Pubkey,
    /// Authorized gateway signer.
    pub gateway: Pubkey,
    /// Authorization PDA bump.
    pub bump: u8,
}

impl GatewayAuthorization {
    /// Serialized account size.
    pub const SPACE: usize = 8 + 32 + 32 + 1;
}

/// Bridged root metadata.
#[account]
pub struct RootState {
    /// Config account this state belongs to.
    pub config: Pubkey,
    /// Bridged Merkle root.
    pub root: [u8; 32],
    /// Proven timestamp.
    pub timestamp: i64,
    /// Opaque gateway proof id.
    pub proof_id: [u8; 32],
    /// Root PDA bump.
    pub bump: u8,
}

impl RootState {
    /// Serialized account size.
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 32 + 1;
}

/// Bridged BabyJubJub public key metadata.
#[account]
pub struct PubkeyState {
    /// Config account this state belongs to.
    pub config: Pubkey,
    /// Issuer schema id (zero-extended) or full 160-bit RP/OPRF key id.
    pub key: [u8; 20],
    /// Public key x-coordinate.
    pub x: [u8; 32],
    /// Public key y-coordinate.
    pub y: [u8; 32],
    /// Opaque gateway proof id.
    pub proof_id: [u8; 32],
    /// Public key PDA bump.
    pub bump: u8,
}

impl PubkeyState {
    /// Serialized account size.
    pub const SPACE: usize = 8 + 32 + 20 + 32 + 32 + 32 + 1;
}

/// Solana-compressed World ID proof plus bundled Merkle root.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofExt {
    /// Compressed G1 `A` point.
    pub proof_a: [u8; 32],
    /// Compressed G2 `B` point.
    pub proof_b: [u8; 64],
    /// Compressed G1 `C` point.
    pub proof_c: [u8; 32],
    /// Merkle root public input.
    pub root: [u8; 32],
}

impl From<ProofExt> for SolanaCompressedProof {
    fn from(value: ProofExt) -> Self {
        Self {
            proof_a: value.proof_a,
            proof_b: value.proof_b,
            proof_c: value.proof_c,
        }
    }
}

/// Uniqueness proof verification arguments.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyArgs {
    /// Nullifier public output.
    pub nullifier: [u8; 32],
    /// Action public input.
    pub action: [u8; 32],
    /// RP id (64-bit; the circuit's public input is scoped to this width).
    pub rp_id: u64,
    /// Nonce public input.
    pub nonce: [u8; 32],
    /// Signal hash public input.
    pub signal_hash: [u8; 32],
    /// Minimum credential expiration timestamp.
    pub expires_at_min: i64,
    /// Credential issuer schema id.
    pub issuer_schema_id: u64,
    /// Minimum credential genesis issuance timestamp.
    pub credential_genesis_issued_at_min: [u8; 32],
    /// Session id, zero for uniqueness proofs.
    pub session_id: [u8; 32],
    /// Solana-compressed proof plus root.
    pub proof: ProofExt,
}

/// Session proof verification arguments.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifySessionArgs {
    /// RP id (64-bit; the circuit's public input is scoped to this width).
    pub rp_id: u64,
    /// Nonce public input.
    pub nonce: [u8; 32],
    /// Signal hash public input.
    pub signal_hash: [u8; 32],
    /// Minimum credential expiration timestamp.
    pub expires_at_min: i64,
    /// Credential issuer schema id.
    pub issuer_schema_id: u64,
    /// Minimum credential genesis issuance timestamp.
    pub credential_genesis_issued_at_min: [u8; 32],
    /// Session id.
    pub session_id: [u8; 32],
    /// Session nullifier tuple `[nullifier, action]`.
    pub session_nullifier: [[u8; 32]; 2],
    /// Solana-compressed proof plus root.
    pub proof: ProofExt,
}

/// Satellite errors.
#[error_code]
pub enum SatelliteError {
    /// A required public key was zero.
    #[msg("zero public key")]
    ZeroPubkey,
    /// Root validity window must be positive.
    #[msg("invalid root validity window")]
    InvalidRootValidityWindow,
    /// Tree depth must be positive.
    #[msg("invalid tree depth")]
    InvalidTreeDepth,
    /// Minimum expiration threshold must be positive.
    #[msg("invalid minimum expiration threshold")]
    InvalidMinExpirationThreshold,
    /// Root cannot be zero.
    #[msg("invalid root")]
    InvalidRoot,
    /// Root is not valid.
    #[msg("invalid merkle root")]
    InvalidMerkleRoot,
    /// Expiration is too old.
    #[msg("expiration too old")]
    ExpirationTooOld,
    /// Issuer schema id has no bridged public key.
    #[msg("unregistered issuer schema id")]
    UnregisteredIssuerSchemaId,
    /// OPRF key id has no bridged public key.
    #[msg("unregistered oprf key id")]
    UnregisteredOprfKeyId,
    /// The Groth16 proof is invalid.
    #[msg("proof invalid")]
    ProofInvalid,
    /// Timestamp must be non-negative.
    #[msg("invalid timestamp")]
    InvalidTimestamp,
    /// State account does not match the expected PDA or config.
    #[msg("invalid state account")]
    InvalidStateAccount,
    /// Signer is not an authorized gateway for this config.
    #[msg("unauthorized gateway")]
    UnauthorizedGateway,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_word_is_big_endian_field_word() {
        let word = u64_word(0x1a6ccf8f70e5de68);

        assert_eq!(&word[..24], &[0u8; 24]);
        assert_eq!(&word[24..], &0x1a6ccf8f70e5de68u64.to_be_bytes());
    }

    #[test]
    fn zero_point_requires_both_coordinates_zero() {
        assert!(is_zero_point(&[0u8; 32], &[0u8; 32]));
        assert!(!is_zero_point(&[1u8; 32], &[0u8; 32]));
        assert!(!is_zero_point(&[0u8; 32], &[1u8; 32]));
    }

    #[test]
    fn key20_from_u64_zero_extends_big_endian() {
        let key = key20_from_u64(0x1a6ccf8f70e5de68);

        assert_eq!(&key[..12], &[0u8; 12]);
        assert_eq!(&key[12..], &0x1a6ccf8f70e5de68u64.to_be_bytes());
        assert_eq!(word20(&key), u64_word(0x1a6ccf8f70e5de68));
    }

    // Cross-validated against a Python `keccak256` (pycryptodome) computation
    // of `keccak256(abi.encodePacked(head, blockHash, data))` where `data =
    // abi.encodeWithSelector(bytes4(keccak256("updateRoot(uint256,uint256,bytes32)")), root, timestamp, proofId)`,
    // matching `Lib.commitChained`'s per-commit hashing exactly.
    #[test]
    fn chain_head_after_commit_matches_solidity_hash_chained_encoding() {
        let prior_head = [0u8; 32];
        let block_hash = [0x01u8; 32];
        let root = u64_word(42);
        let timestamp = u64_word(1234);
        let proof_id = [0xABu8; 32];

        let new_head = chain_head_after_commit(
            &prior_head,
            &block_hash,
            &UPDATE_ROOT_SELECTOR,
            &[&root, &timestamp, &proof_id],
        );

        assert_eq!(
            hex::encode(new_head),
            "3acef09b68939f273742a7b9b942fda91476126d694dd6d83510841beed9ad61"
        );
    }
}
