# TRIAGE SHORT FORM — Veilo privacy_pool

**Title:** Whitelisted relayer can redirect 100% of a position’s source tokens during
`close_position_to_sol`.

**Severity:** Critical — unauthorized redirection of the full source-token balance by
a malicious or compromised whitelisted relayer; net user loss depends on the proof-bound
destination value the victim still receives.

**Program / revision:**
- Program ID: `GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU`
- ProgramData: `T1arFasFzpCgUxCkzWquUwGKwDwrMgygTW8x6PF2bo3`
- ELF SHA-256: `048add2c2d817a044bbbafd2547c7533d8883310f3dcdd8f1fded8fa248f6efb`
- Deployed source claim: `cb1022d9beef220b51da100fb42b6b1edcb02dca` (persists on current public main)

**Vulnerable instruction:** `close_position_to_sol` (staged-legs branch),
`programs/privacy-pool/src/positions.rs:1640-1871`.

**One-sentence attack:** After a user asks Veilo to close a bonding-curve position,
Mallory (a whitelisted relayer) stages a Token-2022 `TransferChecked` that sends the
program-funded position tokens from the ephemeral cosigner ATA to Mallory's ATA, plus
an SPL `CloseAccount` of a pre-funded WSOL ATA that manufactures the native-SOL delta
the handler mistakes for swap proceeds. Source analysis shows the real handler then
consumes the position state; the composition witness validates the value-moving and
cleanup mechanics, not full Groth16-gated handler completion.

**Root cause:** `execute_jup_legs` permits arbitrary System / SPL Token / Token-2022 /
ATA / Jupiter / Memo staged instructions with the relayer-chosen cosigner's signer
privilege, and `SwapParams::hash` does not commit `swap_data_hash` into the Groth16
statement — so the executed instructions are never proof-authorized. `sol_received` is
measured as the cosigner's system-lamport delta, which a pre-funded WSOL close
manufactures; the leftover check inspects the unused executor account.

**Impact:** Attacker receives 100% of the position's source-token balance. The
victim still receives the proof-bound destination note, so net economic loss
depends on that value relative to the source position’s market value. The PoC does
not claim an economic loss percentage from unlike token/SOL base units. Repeatable
across closes routed through the handler; live state
confirmed on mainnet (2 active PositionPDAs, 2026-08-20).

**PoC:** Reproducible Surfpool mainnet-fork composition witness
(`run.sh`), `status=confirmed-staged-legs-theft`. Malicious legs staged through the **real deployed Veilo
`stage_swap_legs`** and executed against real System/SPL/Token-2022 programs. The
harness enforces Veilo's production fee guard with real config injected
(`swap_fee_bps=10`, `min_swap_fee=50_000`, `relayer_fee=6_600_000`); the theft does
not depend on a zero fee. No transaction was submitted to or simulated against mainnet-beta; all executable testing used a local Surfpool mainnet fork.

**Scope boundary:** This is a composition witness, not a full deployed-handler
execution. The Groth16 proof gate is not exercised (server-side swap proving
artifacts are not public); all post-proof value-moving and cleanup mechanics are
runtime-validated. The real handler's nullifier marking and PositionPDA closure are
source-established, not runtime-observed here.

**Duplicate disclosure:** Distinct from the 2026-08-07 "stranded cosigner" report
(extraction vs orphaning); a `cosigner_ata == 0` check would not stop this theft.

**Remediation:** Remove arbitrary staged System/Token instructions; bind the route
(authorization digest) into the SWAP circuit; validate the real source ATA consumed
exactly swap_amount; stop sending claimant secrets to the relayer; pause
`close_position_to_sol` until upgraded.
