# close_position_to_sol staged-legs theft — Surfpool composition witness

**Result: `status=confirmed-staged-legs-theft` — the post-proof attack sequence
executes; the attacker's ATA receives the full source-token balance; the amount
that would back the victim's destination SOL note is supplied entirely by the
relayer's pre-funded WSOL.**

A malicious (or compromised) whitelisted relayer closing a user's bonding-curve
position through `close_position_to_sol` can redirect the entire source-token
balance to its own account. The victim still receives the proof-committed destination
note, so net economic loss depends on that value relative to the source position’s
market value.

## What this witness proves (composition, not full-handler completion)

The **real deployed Veilo binary** is used for `stage_swap_legs` (creation and
population of the actual `SwapLegsBuffer`). A separate harness then reproduces the
post-proof mechanics of `close_position_to_sol` / `execute_jup_legs` and executes
them against the real System / SPL Token / Token-2022 programs on a Surfpool
mainnet fork. **Full completion of the deployed `close_position_to_sol`
instruction is not demonstrated** because the production SWAP proving artifacts
are unavailable.

| # | Element | Evidence |
|---|---|---|
| 1 | The malicious legs are accepted by the **deployed Veilo binary** (`stage_swap_legs` instruction, no allowlist) | Stage tx confirmed against `GYy4kM6…7fFU` on the fork |
| 2 | A staged **Token-2022 TransferChecked** leg moves the full `swap_amount` from the cosigner ATA to Mallory's ATA, using the cosigner's manufactured signer privilege | `attacker_meme_ata = 100_000_000_000` |
| 3 | A staged **SPL Token CloseAccount** of a pre-funded WSOL ATA manufactures the positive native-SOL delta the handler mistakes for swap proceeds | `sol_received ≈ 6.50 SOL` with no swap executed |
| 4 | The runtime `sha256(legs) == swap_data_hash` check passes but is **not proof-authorized** (`SwapParams::hash` omits `swap_data_hash`, swap.rs:102-127) | Legs executed |
| 5 | The source ATA reaches zero and closes; the leftover check inspects the unused executor account (positions.rs:1770-1774) | `cosigner_meme_ata = None`, `executor_source` untouched |
| 6 | The destination SOL-vault value is supplied entirely by the relayer's pre-funded WSOL, not by any swap | `sol_vault = 6_495_439_280` |

The production **fee guard is enforced** by the harness: `relayer_fee >=
max(min_swap_fee, sol_received * swap_fee_bps / 10_000)` with the destination
pool's real config injected (`swap_fee_bps = 10`, `min_swap_fee = 50_000`,
`relayer_fee = 6_600_000`). The theft does not depend on a zero fee; Mallory
simply fronts a legitimate fee. The harness's private-note issuance, real
nullifier marking, and `PositionPDA` closure are **not** executed — those are
established by source analysis of the real handler, not observed here.

## Source citations (frozen revision `d81bb1f8d95738ef0fc13fd666333dfaf4757f71`)

- `positions.rs:1640-1718` — staged-legs close core: cosigner ATA transfer,
  `before = cosigner.lamports()`, leg execution, `sol_received` delta
- `positions.rs:1811-1871` — `JupLeg` encoding + `execute_jup_legs` allowlist
  (System / SPL / Token-2022 / ATA / Jupiter / Memo) and signer manufacturing
  (`is_signer = key == executor || key == cosigner`)
- `positions.rs:1895-1908` — `execute_dex_swap` staged-buffer branch:
  `sha256(buffer.legs) == swap_data_hash` runtime check only
- `positions.rs:2007-2040` — `token_2022_transfer_checked` raw CPI
- `positions.rs:2075-2103` — `close_cosigner_ata_if_empty`
- `positions.rs:1770-1774` — ineffective executor-source leftover check
- `swap.rs:102-127` — `SwapParams::hash` omits `swap_data_hash` (proof gap)
- `positions.rs:2415-2427` — `stage_swap_legs` (no allowlist; sentinel-only check)

## Scope boundary (honest)

This is a **composition witness**, not a full end-to-end execution of the deployed
`close_position_to_sol` instruction. The Groth16 proof gate and the surrounding
privacy-pool accounting (Merkle commitment insertion, private-note issuance, real
nullifier marking, `PositionPDA` closure) are **not** executed: the production SWAP
proving artifacts (`swap.r1cs` / `swap_final.zkey` / `swap.wasm`) are server-side
and not public. The value-moving, staged-CPI, SOL-delta, fee-validation, and cleanup
mechanics relevant to the theft are reproduced in `harness-lib.rs` and executed
against the real System / SPL
Token / Token-2022 programs on a Surfpool mainnet fork. The malicious legs were
staged through the **real deployed Veilo program**, and the attacker-controlled
keys (cosigner, relayer) are fresh — proving the theft needs no user wallet
signature beyond the production close flow (whose claimant key the released wallet
sends to the relayer; see the submission report). The real handler's nullifier
marking and `PositionPDA` closure are established by source analysis, not observed
here.

## Gist file layout

This Gist is intentionally flat because GitHub Gists do not support directories.
`harness-Cargo.toml` points directly to `harness-lib.rs`, `driver-Cargo.toml` points
directly to `driver-main.rs`, and `run.sh` uses those flat manifest names.

## Reproduction

```bash
bash run.sh
```

Requires: `surfpool` (v1.3+), `cargo build-sbf`, network (forks `api.mainnet-beta.solana.com`).

Observed `run-output.txt` (post-fee-guard run):

```text
status=confirmed-staged-legs-theft
stolen_tokens=100000000000
victim_note_backing=6495439280
loss_fraction=95.0%
```

Fixture numbers: `swap_amount = 100_000_000_000` position tokens;
`dest_amount = 5_000_000_000`; destination SOL-pool config `swap_fee_bps = 10`,
`min_swap_fee = 50_000`; `relayer_fee = 6_600_000` (satisfies the real guard);
Mallory fronts `6_500_000_000` lamports of WSOL. `victim_note_backing` is the
lamports deposited into the SOL-vault fixture (`sol_received - relayer_fee`), i.e.
the amount that would back the victim's destination SOL note — supplied entirely by
the relayer, not by any swap. `loss_fraction = 1 - victim_note_backing / swap_amount` is a **legacy fixture-only
ratio between unlike base units** (source-token units versus lamports). It is not an
economic-loss percentage and is not used to support severity.
(≈ the user's committed minimum, plus the legitimate relayer fee and a safety
margin). The two malicious legs:

1. Token-2022 `TransferChecked` (disc `0x0c`): `cosigner_meme_ata → attacker_meme_ata`,
   `amount = swap_amount`, authority = cosigner.
2. SPL Token `CloseAccount` (disc `0x09`): `cosigner_wsol_ata → cosigner`
   (converts pre-funded WSOL into the measured native-SOL delta).

## Versions

- surfpool 1.3.0 (mainnet fork, datasource `https://api.mainnet-beta.solana.com`)
- cargo 1.95.0-nightly, solana-program 2.1.21 (harness), solana-* modular 2.6-3.1 (driver)
- Target: `privacy_pool` `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
- Harness SBF SHA-256: `3524691d5f902b8ef88c584f7d47af58926913cebb7469e22c32db9bd1eaa76a`

## Safety

No transaction was submitted to or simulated against mainnet-beta. All executable testing occurred against a local Surfpool mainnet fork using fixture funds and throwaway keys.
