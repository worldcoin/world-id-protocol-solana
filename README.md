# World ID Protocol — Solana

Solana smart contracts for World ID. This repo holds the on-chain program
only: an [Anchor](https://www.anchor-lang.com/)-based "satellite" program that
stores bridged World ID state (Merkle roots, issuer keys, OPRF keys) and
verifies World ID Groth16 uniqueness/session proofs on-chain.

The off-chain bridge/relay that pushes state from World Chain into this
program lives in [`world-id-protocol`](https://github.com/worldcoin/world-id-protocol)
(`services/relay`). This split keeps chain-specific contract code and its
deployment lifecycle independent from the relay's release cadence.

## Layout

The on-chain program is a single crate, split into two modules:

```
programs/world-id-solana/
  Cargo.toml
  src/
    lib.rs       # Anchor program: accounts, instructions, PDAs
    verifier.rs  # Groth16 verifier adapter (delegates to groth16-solana / solana-bn254)
```

`verifier.rs` only exists as a separate module for readability — it has no
independent versioning or publishing story. If you're looking for the
account layout, instruction handlers, or PDA seeds, start in `lib.rs`. If
you're looking for proof/curve verification, start in `verifier.rs`.

Alongside it:

```
tools/deploy/
  src/main.rs  # initialize / add-gateway / remove-gateway / set-owner, used by scripts/deploy.sh
scripts/
  deploy.sh    # single entrypoint: build -> deploy -> IDL -> initialize -> add-gateway
```

`tools/deploy` handles the post-deploy setup steps that `solana program
deploy` doesn't do for you — see [Deployment](#deployment) below.

## Dependency on `world-id-protocol`

The verifier module needs `world_id_primitives::ZeroKnowledgeProof` (the
canonical proof encoding shared across all World ID chain integrations). That
crate isn't vendored here — it's pulled in as documented below so this repo
never drifts from the canonical definition.

## Prerequisites

- Rust (see `rust-version` in `Cargo.toml`)
- [Solana CLI](https://docs.anza.xyz/cli/install) (`solana --version`)
- [Anchor CLI](https://www.anchor-lang.com/docs/installation) (`avm install latest && avm use latest`)

## Building

```sh
# Anchor build (produces the IDL + .so under target/)
anchor build

# Equivalent plain-cargo build, if you don't need the IDL regenerated
cargo build-sbf --manifest-path programs/world-id-solana/Cargo.toml --sbf-out-dir target/deploy
```

## Testing

```sh
cargo test -p world-id-solana
```

On-chain integration tests (LiteSVM-based end-to-end tests exercising the
relay against this program) live in `world-id-protocol`'s `services/relay`
test suite, not here — see that repo's README for running them.

## Calling `verify`/`verify_session`

Groth16/BN254 pairing verification is compute-intensive and **exceeds
Solana's default 200,000 compute-unit per-instruction limit**. Every caller
must prepend a compute-budget instruction requesting a higher limit, or the
transaction fails with `exceeded CUs meter at BPF instruction`:

```rust
let compute_budget_ix =
    solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000); // network max
// include compute_budget_ix as the first instruction in the same transaction as verify/verify_session
```

## Deployment

`scripts/deploy.sh` is the single entrypoint for the whole pipeline: build →
`solana program deploy` → push the IDL → `initialize` → `add-gateway`. It's
entirely config-driven — copy `.env.example` to `.env`, fill in the values,
and run it with no arguments:

```sh
cp .env.example .env
# edit .env: SOLANA_RPC_URL, SOLANA_AUTHORITY_KEYPAIR, and (first deploy only)
# SOLANA_PROGRAM_KEYPAIR / GATEWAY_PUBKEY
./scripts/deploy.sh
```

It's safe to re-run: `initialize`/`add-gateway` use Anchor's `init` constraint
under the hood, so a repeat call against an already-initialized program or
already-authorized gateway fails cleanly (logged as a non-fatal warning)
instead of corrupting state — re-running after changing only
`SOLANA_PROGRAM_KEYPAIR` (for an upgrade) just skips those steps.

Never point `SOLANA_AUTHORITY_KEYPAIR` at a locally-generated throwaway
keypair for testnet/mainnet — use the multisig/PDA authority designated for
this program.

Under the hood, `scripts/deploy.sh` runs:

1. `cargo build-sbf --manifest-path programs/world-id-solana/Cargo.toml --sbf-out-dir target/deploy`
2. `solana program deploy` (first deploy, keyed by `SOLANA_PROGRAM_KEYPAIR`; upgrade otherwise, keyed by `PROGRAM_ID`)
3. `anchor idl init`/`anchor idl upgrade` (skipped if the `anchor` CLI isn't installed — optional)
4. `cargo run -p world-id-solana-deploy -- ... initialize ...` (see `tools/deploy/src/main.rs` — a thin wrapper over the official `anchor-client` Rust crate, not hand-rolled instruction encoding)
5. The same tool's `add-gateway`, if `GATEWAY_PUBKEY` is set

Finally, **tag the release** (`git tag solana-vX.Y.Z`) so the relay repo can
pin a specific commit/tag when it depends on this program via git (see
below).

Rollout notes:
- Treat mainnet upgrades like any other irreversible-ish production change:
  deploy to devnet/testnet first, run the relay's e2e suite against it, then
  promote.
- Anchor program upgrades replace the program's executable but preserve
  account data — verify any account/state schema changes are backwards
  compatible (additive only) before upgrading a cluster with live state.
- Keep the upgrade authority off of individual laptops for testnet/mainnet;
  use a Squads multisig or similar.

## Local development across the two repos

`world-id-protocol`'s relay code depends on this program's Rust types (the
generated IDL and Anchor account/instruction types) to build transactions and
run local end-to-end tests. To avoid git submodules, that dependency is
expressed as a normal Cargo dependency that can be pointed at either:

- this repo on GitHub (the default, for CI and normal development), or
- a local checkout of this repo on disk (for iterating on both repos at once).

In `world-id-protocol`, the relevant `Cargo.toml` (e.g. `services/relay`)
declares:

```toml
[dependencies]
world-id-solana = { git = "https://github.com/worldcoin/world-id-protocol-solana" }
```

To work on both repos locally at the same time, clone this repo as a sibling
of `world-id-protocol` and add a `[patch]` section to the *root*
`Cargo.toml` of `world-id-protocol` (do not add it to `services/relay`'s own
`Cargo.toml` — patches only take effect from a workspace root):

```toml
# world-id-protocol/Cargo.toml
[patch."https://github.com/worldcoin/world-id-protocol-solana"]
world-id-solana = { path = "../world-id-protocol-solana/programs/world-id-solana" }
```

With that patch in place, `cargo build`/`cargo test` in `world-id-protocol`
will resolve `world-id-solana` from your local working copy, so edits here
are picked up immediately without publishing or pushing. Remove (or comment
out) the `[patch]` block before committing — it's a local-only override, not
something CI should use. `Cargo.lock` will reflect whichever source was
active at the last `cargo` invocation, so avoid committing a lockfile change
that was only produced under the local patch.

This repo, in turn, resolves `world-id-primitives` from `world-id-protocol`
the same way — by default via `git`, overridable with a local `[patch]` here
if you're changing both the primitive types and this program at once:

```toml
# world-id-protocol-solana/Cargo.toml
[patch."https://github.com/worldcoin/world-id-protocol"]
world-id-primitives = { path = "../world-id-protocol/crates/primitives" }
```
