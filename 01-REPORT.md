# Veilo privacy_pool — Critical: Whitelisted relayer can redirect 100% of a position’s source tokens during `close_position_to_sol`

**Program:** `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
**Severity:** Critical — direct theft of a user's position tokens by a malicious or compromised whitelisted relayer.
**Status:** Confirmed via a reproducible Surfpool mainnet-fork composition witness (`status=confirmed-staged-legs-theft`).

---

## One-sentence attack

A whitelisted relayer asked to close a user's bonding-curve position stages two
Token/System instructions instead of a swap: a Token-2022 `TransferChecked` that
moves the entire proof-funded position balance from the ephemeral cosigner ATA to
the relayer's own ATA, and an SPL `CloseAccount` of a pre-funded WSOL ATA that
manufactures the native-SOL delta the handler mistakes for swap proceeds. Source
analysis shows the real handler subsequently consumes the position state; the victim
still receives the proof-bound destination note.

> The **composition witness** confirms the post-proof attack sequence. Full
> completion of the deployed `close_position_to_sol` instruction was not demonstrated
> because the production SWAP proving artifacts are unavailable.

The attacker does **not** need the admin key, a forged Groth16 proof, a malicious
mint, a malicious token program, a compromised DEX, or a separate user wallet
signature.

---

## Trust boundary violated

The repository's own audit guidance states relayers are trusted for *submission and
liveness*, **not** for custody of private notes, and that every `remaining_accounts`
CPI must be constrained by program, signer, ATA, amount and proof binding. The
`PositionPDA.claimant` field exists specifically to stop a whitelisted relayer from
closing a victim's position with another user's proof. This finding breaks that
boundary: the relayer controls which instructions execute and which signer privilege
they receive, so it controls where the position tokens go.

### Production reachability (supporting evidence only)

Static analysis of the released Veilo Wallet close flow found that the client sends
the claimant signing material and private position-note data to the relayer endpoint
and receives a final transaction signature; the client does not independently sign
the final close transaction. This evidence is included only to establish that the
normal production architecture can give the whitelisted relayer the claimant signing
capability needed to reach the in-scope on-chain path. The wallet/backend itself is
**not** the reported vulnerability.

---

## Vulnerable on-chain flow (frozen revision `d81bb1f8…`; persists on current public main)

1. **Handler funds a relayer-chosen cosigner ATA with the full position.**
   `close_position_to_sol` derives the canonical Token-2022 ATA for
   `remaining_accounts[1]` (the relayer-selected cosigner), creates it, and transfers
   `swap_amount` from the position vault into it (positions.rs:1658-1692).

2. **Staged legs may be arbitrary signer-capable Token/System instructions.**
   `execute_jup_legs` (positions.rs:1811-1871) accepts a Borsh `Vec<JupLeg>`; each leg
   controls its program ID, account indices and bytes. The allowlist is **not**
   limited to Jupiter (positions.rs:1819-1826):
   ```rust
   *p == system_program::ID || *p == token::ID || *p == TOKEN_2022_PROGRAM_ID
     || *p == ATA || *p == JUPITER || *p == MEMO
   ```
   For every account whose key equals the executor or the cosigner, a signer meta is
   manufactured (`is_signer = key == executor || key == cosigner`, positions.rs:1853).
   The cosigner signs the outer transaction, so a staged Token-2022 `TransferChecked`
   uses the cosigner as authority and moves the position tokens directly to the
   relayer's ATA. No Jupiter instruction is required.

3. **The staged hash is runtime-consistent but not proof-authorized.**
   The handler checks only `sha256(buffer.legs) == swap_params.swap_data_hash`
   (positions.rs:1906-1907) — it proves the executed bytes equal the bytes named by
   the transaction, not that the user authorized them. `SwapParams::hash`, which
   produces the `swapParamsHash` checked by Groth16, hashes only the mint pair and
   `minAmountOut/deadline/destAmount` (swap.rs:102-127) — **`swap_data_hash` is absent
   from the current circuit** (also stated in the source comments around the staged
   buffer design). The relayer can
   therefore substitute any allowed instruction list without touching the ten
   proof-bound public inputs.

4. **The required SOL result is manufactured, not earned.**
   `close_position_to_sol` measures only the increase in the cosigner's *system*
   lamports across the staged instructions (`before = cosigner.lamports()`;
   `sol_received = after - before`, positions.rs:1699-1718). A pre-funded WSOL ATA is
   a separate account; a staged SPL `CloseAccount` leg credits its lamports to the
   cosigner system account, producing a positive `sol_received` with no swap.

5. **Cleanup checks pass after theft.**
   - `close_cosigner_ata_if_empty` closes the real source ATA once it is empty
     (positions.rs:1720-1727, 2075-2103) — the theft drains it completely.
   - The later leftover check inspects `executor_source_token` (positions.rs:1770-1774),
     the **wrong** account: the position tokens were placed in the cosigner ATA, not the
     executor ATA, so the executor account is zero and the check passes.
   - The program then subtracts the full `swap_amount` from the position vault record,
     marks the input nullifiers spent, and closes the `PositionPDA`. The victim cannot
     retry.

## Deterministic two-instruction exploit

1. **Token-2022 `TransferChecked`** (disc `0x0c`): `cosigner_meme_ata → attacker_meme_ata`,
   `amount = swap_amount`, `authority = cosigner`.
2. **SPL `CloseAccount`** (disc `0x09`): `cosigner_wsol_ata → cosigner`
   (converts pre-funded WSOL into the measured native-SOL delta).

For any close whose proof-bound `destAmount`/`minAmountOut` is materially below the
economic value of the source position, Mallory can front WSOL to satisfy those terms
plus the configured fee while redirecting the full source-token balance to the
attacker. The staged route itself remains unbound to the proof.

---

## Impact

- The attacker receives **100% of the position's source-token balance**. The victim
  still receives the proof-bound destination note, so net economic loss depends on
  the committed `destAmount` relative to the source position’s market value. The PoC
  intentionally does **not** claim an economic loss percentage because source-token
  base units and SOL lamports are not directly comparable.
- Repeatable across users and positions routed through this handler.
- A read-only mainnet snapshot (2026-08-20) found two active `PositionPDA` accounts
  with nonzero per-mint vault records — the feature is live with reachable state.

---

## Reproduction — Surfpool mainnet-fork composition witness

`poc/close-position-theft-surfpool-poc/` (in this archive) contains:

- `harness/` — a line-cited SBF copy of the post-proof mechanics, including Veilo's
  production fee guard (`relayer_fee >= max(min_swap_fee, received * swap_fee_bps / 10_000)`)
  with the destination pool's real config injected
- `driver/` — Rust driver: deploys the harness, provisions Token-2022 state,
  **stages the malicious legs through the real deployed Veilo `stage_swap_legs`**,
  executes, and asserts
- `run.sh` — one-command reproduction
- `run-output.txt` — captured confirmed output

Run: `bash run.sh` (requires `surfpool` v1.3+, `cargo build-sbf`, network for the
mainnet fork). Observed, reproducible output:

```text
status=confirmed-staged-legs-theft
stolen_tokens=100000000000
victim_note_backing=6495439280
loss_fraction=95.0%  # fixture-only ratio of unlike base units; not an economic loss percentage
```

`victim_note_backing` is the lamports deposited into the SOL-vault fixture
(`sol_received - relayer_fee`) — the amount that would back the victim's
destination SOL note, supplied entirely by the relayer's pre-funded WSOL, not by
any swap. The printed `loss_fraction` is a legacy fixture-only ratio between unlike
base units and is not used as an economic-loss claim. The malicious legs were accepted by the **real deployed Veilo binary's
`stage_swap_legs`** (stage tx confirmed on a mainnet fork), and the post-proof
value-moving/cleanup path executed against the real System / SPL Token / Token-2022
programs.

## Scope boundary

This is a **composition witness**, not a full end-to-end execution of the deployed
`close_position_to_sol` instruction. The Groth16 proof gate itself is not exercised
because the production **swap** proving artifacts (`swap.r1cs` / `swap_final.zkey` /
`swap.wasm`) are server-side and not public. The value-moving, staged-CPI, SOL-delta,
fee-validation, and cleanup mechanics relevant to the theft are reproduced in the
harness and executed on a Surfpool mainnet fork. The harness
**does not** execute the real handler's Merkle commitment insertion / private-note
issuance, real nullifier marking, or `PositionPDA` closure — those are established
by source analysis of the deployed handler, not observed here.

## Duplicate / overlap disclosure

A public fork report (2026-08-07) described a benign or malformed route leaving
tokens *stranded* in the cosigner ATA. That is a different primitive: this finding
**deliberately transfers** the tokens to an attacker-controlled account and leaves
the cosigner ATA empty. A patch adding only `cosigner_meme_ata.amount == 0` would
stop the stranding variant but **not** this theft. Both touch the same handler and
staged-leg mechanism, so the overlap is disclosed rather than hidden.

## Recommended remediation

1. Do **not** allow System / SPL Token / Token-2022 / ATA instructions as arbitrary
   staged legs; if staged Jupiter execution must remain, accept only the canonical
   Jupiter program and parse its discriminators/account layouts, and require source
   authority, source ATA, destination, mints and amount to match handler-derived and
   proof-bound values.
2. Measure the **real** source account: snapshot `cosigner_meme_ata` before/after and
   require exactly `swap_amount` consumed by a validated Jupiter instruction; reject
   extra token destinations; remove or supplement the executor-source check.
3. Upgrade the SWAP circuit/VK so `swap_data_hash` (or a canonical authorization
   digest) is part of the Groth16 public statement. A runtime equality check to an
   attacker-selected hash is not authorization.
4. Stop sending claimant/private-note secrets to the relayer; sign the final
   transaction after displaying the exact route and outputs, or scope a signature to
   the close authorization digest.
5. Pause `close_position_to_sol` and any endpoint that invokes its staged branch
   until an upgrade lands; rotating relayer keys alone is not a durable fix.

## Environment / provenance

- surfpool 1.3.0 (mainnet fork, datasource `https://api.mainnet-beta.solana.com`)
- cargo 1.95.0-nightly; harness `solana-program` 2.1.21; driver solana-* modular 2.6-3.1
- Deployed source claim: `cb1022d9beef220b51da100fb42b6b1edcb02dca`;
  ProgramData slot `432860998`; ELF SHA-256 `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb`
- Vulnerable behavior also present in frozen revision `d81bb1f8d95738ef0fc13fd666333dfaf4757f71`
- Harness SBF SHA-256 `3524691d5f902b8ef88c584f7d47af58926913cebb7469e22c32db9bd1eaa76a`
- No transaction was submitted to or simulated against mainnet-beta. All executable testing occurred against a local Surfpool mainnet fork using fixture funds and throwaway keys.
