#![cfg(target_os = "solana")]

use {solana_account_info::AccountInfo, solana_program_error::ProgramError, solana_pubkey::Pubkey};
use std::vec::Vec;

// Declare the custom syscall that we expect to be registered.
// This matches the `sol_burn_cus` syscall from the test.
extern "C" {
    fn sol_burn_cus(to_burn: u64) -> u64;
    fn sol_inspect(val: u64);
}

solana_program_entrypoint::entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    input: &[u8],
) -> Result<(), ProgramError> {
    let to_burn = input
        .get(0..8)
        .and_then(|bytes| bytes.try_into().map(u64::from_le_bytes).ok())
        .ok_or(ProgramError::InvalidInstructionData)?;

    let mut fibs: Vec<u64> = vec![1, 1];
    for _ in 1..to_burn {
        fibs.push(fibs[fibs.len() - 1] + fibs[fibs.len() - 2]);
    }
    let value = fibs.last().unwrap() % 7;

    // Call the custom syscall to burn CUs.
    unsafe {
        sol_inspect(fibs.last().unwrap() % 7);
        //sol_burn_cus();
    }

    Ok(())
}
