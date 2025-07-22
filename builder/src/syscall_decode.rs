use {
    super::*,
    //solana_bpf_loader_program::{translate_inner, translate_slice_inner, translate_type_inner},
    solana_bpf_loader_program::syscalls::{SyscallError,VmSlice},
    solana_sbpf::memory_region::AccessType,
    solana_stable_layout::stable_instruction::StableInstruction,
    //std::{mem, ptr},
};

type Error = Box<dyn std::error::Error>;

const MAX_CPI_INSTRUCTION_DATA_LEN: u64 = 10 * 1024;

/// Maximum signers
const MAX_SIGNERS: usize = 16;
/// Maximum number of seeds
pub const MAX_SEEDS: usize = 16;

fn address_is_aligned<T>(address: u64) -> bool {
    (address as *mut T as usize)
        .checked_rem(align_of::<T>())
        .map(|rem| rem == 0)
        .expect("T to be non-zero aligned")
}

// Do not use this directly
#[macro_export]
macro_rules! translate_inner {
    ($memory_mapping:expr, $access_type:expr, $vm_addr:expr, $len:expr $(,)?) => {
        Result::<u64, Error>::from(
            $memory_mapping
                .map($access_type, $vm_addr, $len)
                .map_err(|err| err.into()),
        )
    };
}
// Do not use this directly
#[macro_export]
macro_rules! translate_type_inner {
    ($memory_mapping:expr, $access_type:expr, $vm_addr:expr, $T:ty, $check_aligned:expr $(,)?) => {{
        let host_addr = translate_inner!(
            $memory_mapping,
            $access_type,
            $vm_addr,
            size_of::<$T>() as u64
        )?;
        if !$check_aligned {
            Ok(unsafe { std::mem::transmute::<u64, &mut $T>(host_addr) })
        } else if !address_is_aligned::<$T>(host_addr) {
            Err(SyscallError::UnalignedPointer.into())
        } else {
            Ok(unsafe { &mut *(host_addr as *mut $T) })
        }
    }};
}
// Do not use this directly
#[macro_export]
macro_rules! translate_slice_inner {
    ($memory_mapping:expr, $access_type:expr, $vm_addr:expr, $len:expr, $T:ty, $check_aligned:expr $(,)?) => {{
        if $len == 0 {
            return Ok(&mut []);
        }
        let total_size = $len.saturating_mul(size_of::<$T>() as u64);
        if isize::try_from(total_size).is_err() {
            return Err(SyscallError::InvalidLength.into());
        }
        let host_addr = translate_inner!($memory_mapping, $access_type, $vm_addr, total_size)?;
        if $check_aligned && !address_is_aligned::<$T>(host_addr) {
            return Err(SyscallError::UnalignedPointer.into());
        }
        Ok(unsafe { std::slice::from_raw_parts_mut(host_addr as *mut $T, $len as usize) })
    }};
}

fn translate_type<'a, T>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a T, Error> {
    translate_type_inner!(memory_mapping, AccessType::Load, vm_addr, T, check_aligned)
        .map(|value| &*value)
}

fn translate_slice<'a, T>(
    memory_mapping: &'a MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a [T], Error> {
    translate_slice_inner!(
        memory_mapping,
        AccessType::Load,
        vm_addr,
        len,
        T,
        check_aligned,
    )
    .map(|value| &*value)
}

// Safety: This will invalidate previously translated references.
// No other translated references shall be live when calling this.
// Meaning it should generally be at the beginning or end of a syscall and
// it should only be called once with all translations passed in one call.
#[macro_export]
macro_rules! translate_mut {
    (internal, $memory_mapping:expr, $check_aligned:expr, &mut [$T:ty], $vm_addr_and_element_count:expr) => {{
        let slice = translate_slice_mut::<$T>(
            $memory_mapping,
            $vm_addr_and_element_count.0,
            $vm_addr_and_element_count.1,
            $check_aligned,
        )?;
        let host_addr = slice.as_ptr() as usize;
        (slice, host_addr, std::mem::size_of::<$T>().saturating_mul($vm_addr_and_element_count.1 as usize))
    }};
    (internal, $memory_mapping:expr, $check_aligned:expr, &mut $T:ty, $vm_addr:expr) => {{
        let reference = translate_type_mut::<$T>(
            $memory_mapping,
            $vm_addr,
            $check_aligned,
        )?;
        let host_addr = reference as *const _ as usize;
        (reference, host_addr, std::mem::size_of::<$T>())
    }};
    ($memory_mapping:expr, $check_aligned:expr, $(let $binding:ident : &mut $T:tt = map($vm_addr:expr $(, $element_count:expr)?) $try:tt;)+) => {
        // This ensures that all the parameters are collected first so that if they depend on previous translations
        $(let $binding = ($vm_addr $(, $element_count)?);)+
        // they are not invalidated by the following translations here:
        $(let $binding = translate_mut!(internal, $memory_mapping, $check_aligned, &mut $T, $binding);)+
        let host_ranges = [
            $(($binding.1, $binding.2),)+
        ];
        for (index, range_a) in host_ranges.get(..host_ranges.len().saturating_sub(1)).unwrap().iter().enumerate() {
            for range_b in host_ranges.get(index.saturating_add(1)..).unwrap().iter() {
                if !is_nonoverlapping(range_a.0, range_a.1, range_b.0, range_b.1) {
                    return Err(SyscallError::CopyOverlapping.into());
                }
            }
        }
        $(let $binding = $binding.0;)+
    };
}

pub fn translate_instruction_rust(
    addr: u64,
    memory_mapping: &MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<StableInstruction, Error> {
    let ix = translate_type::<StableInstruction>(
        memory_mapping,
        addr,
        invoke_context.get_check_aligned(),
    )?;
    let account_metas = translate_slice::<AccountMeta>(
        memory_mapping,
        ix.accounts.as_vaddr(),
        ix.accounts.len(),
        invoke_context.get_check_aligned(),
    )?;
    let data = translate_slice::<u8>(
        memory_mapping,
        ix.data.as_vaddr(),
        ix.data.len(),
        invoke_context.get_check_aligned(),
    )?
    .to_vec();

    let max_data_len = MAX_CPI_INSTRUCTION_DATA_LEN;
    let data_len = data.len() as u64;
    if data_len > max_data_len {
        return Err(Box::new(SyscallError::MaxInstructionDataLenExceeded {
            data_len,
            max_data_len,
        }));
    }

    let mut accounts = Vec::with_capacity(account_metas.len());
    #[allow(clippy::needless_range_loop)]
    for account_index in 0..account_metas.len() {
        #[allow(clippy::indexing_slicing)]
        let account_meta = &account_metas[account_index];
        if unsafe {
            std::ptr::read_volatile(&account_meta.is_signer as *const _ as *const u8) > 1
                || std::ptr::read_volatile(&account_meta.is_writable as *const _ as *const u8)
                    > 1
        } {
            return Err(Box::new(InstructionError::InvalidArgument));
        }
        accounts.push(account_meta.clone());
    }

    Ok(StableInstruction {
        accounts: accounts.into(),
        data: data.into(),
        program_id: ix.program_id,
    })
}

/// Rust representation of C's SolInstruction
#[derive(Debug)]
#[repr(C)]
struct SolInstruction {
    program_id_addr: u64,
    accounts_addr: u64,
    accounts_len: u64,
    data_addr: u64,
    data_len: u64,
}

/// Rust representation of C's SolAccountMeta
#[derive(Debug)]
#[repr(C)]
struct SolAccountMeta {
    pubkey_addr: u64,
    is_writable: bool,
    is_signer: bool,
}

pub fn translate_instruction_c(
    addr: u64,
    memory_mapping: &MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<StableInstruction, Error> {
    let ix_c = translate_type::<SolInstruction>(
        memory_mapping,
        addr,
        invoke_context.get_check_aligned(),
    )?;

    let program_id = translate_type::<Pubkey>(
        memory_mapping,
        ix_c.program_id_addr,
        invoke_context.get_check_aligned(),
    )?;
    let account_metas = translate_slice::<SolAccountMeta>(
        memory_mapping,
        ix_c.accounts_addr,
        ix_c.accounts_len,
        invoke_context.get_check_aligned(),
    )?;
    let data = translate_slice::<u8>(
        memory_mapping,
        ix_c.data_addr,
        ix_c.data_len,
        invoke_context.get_check_aligned(),
    )?
    .to_vec();

    let max_data_len = MAX_CPI_INSTRUCTION_DATA_LEN;
    let data_len = data.len() as u64;
    if data_len > max_data_len {
        return Err(Box::new(SyscallError::MaxInstructionDataLenExceeded {
            data_len,
            max_data_len,
        }));
    }

    let mut accounts = Vec::with_capacity(ix_c.accounts_len as usize);
    #[allow(clippy::needless_range_loop)]
    for account_index in 0..ix_c.accounts_len as usize {
        #[allow(clippy::indexing_slicing)]
        let account_meta = &account_metas[account_index];
        if unsafe {
            std::ptr::read_volatile(&account_meta.is_signer as *const _ as *const u8) > 1
                || std::ptr::read_volatile(&account_meta.is_writable as *const _ as *const u8)
                    > 1
        } {
            return Err(Box::new(InstructionError::InvalidArgument));
        }
        let pubkey = translate_type::<Pubkey>(
            memory_mapping,
            account_meta.pubkey_addr,
            invoke_context.get_check_aligned(),
        )?;
        accounts.push(AccountMeta {
            pubkey: *pubkey,
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        });
    }

    Ok(StableInstruction {
        accounts: accounts.into(),
        data: data.into(),
        program_id: *program_id,
    })
}

pub fn translate_signers_rust(
    program_id: &Pubkey,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    memory_mapping: &MemoryMapping,
    invoke_context: &InvokeContext,
) -> Result<Vec<Pubkey>, Error> {
    let mut signers = Vec::new();
    if signers_seeds_len > 0 {
        let signers_seeds = translate_slice::<VmSlice<VmSlice<u8>>>(
            memory_mapping,
            signers_seeds_addr,
            signers_seeds_len,
            invoke_context.get_check_aligned(),
        )?;
        if signers_seeds.len() > MAX_SIGNERS {
            return Err(Box::new(SyscallError::TooManySigners));
        }
        for signer_seeds in signers_seeds.iter() {
            let untranslated_seeds = translate_slice::<VmSlice<u8>>(
                memory_mapping,
                signer_seeds.ptr(),
                signer_seeds.len(),
                invoke_context.get_check_aligned(),
            )?;
            if untranslated_seeds.len() > MAX_SEEDS {
                return Err(Box::new(InstructionError::MaxSeedLengthExceeded));
            }
            let seeds = untranslated_seeds
                .iter()
                .map(|untranslated_seed| {
                    untranslated_seed
                        .translate(memory_mapping, invoke_context.get_check_aligned())
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let signer = Pubkey::create_program_address(&seeds, program_id)
                .map_err(SyscallError::BadSeeds)?;
            signers.push(signer);
        }
        Ok(signers)
    } else {
        Ok(vec![])
    }
}


/// Rust representation of C's SolSignerSeed
#[derive(Debug)]
#[repr(C)]
struct SolSignerSeedC {
    addr: u64,
    len: u64,
}

/// Rust representation of C's SolSignerSeeds
#[derive(Debug)]
#[repr(C)]
struct SolSignerSeedsC {
    addr: u64,
    len: u64,
}

pub fn translate_signers_c(
    program_id: &Pubkey,
    signers_seeds_addr: u64,
    signers_seeds_len: u64,
    memory_mapping: &MemoryMapping,
    invoke_context: &InvokeContext,
) -> Result<Vec<Pubkey>, Error> {
    if signers_seeds_len > 0 {
        let signers_seeds = translate_slice::<SolSignerSeedsC>(
            memory_mapping,
            signers_seeds_addr,
            signers_seeds_len,
            invoke_context.get_check_aligned(),
        )?;
        if signers_seeds.len() > MAX_SIGNERS {
            return Err(Box::new(SyscallError::TooManySigners));
        }
        Ok(signers_seeds
            .iter()
            .map(|signer_seeds| {
                let seeds = translate_slice::<SolSignerSeedC>(
                    memory_mapping,
                    signer_seeds.addr,
                    signer_seeds.len,
                    invoke_context.get_check_aligned(),
                )?;
                if seeds.len() > MAX_SEEDS {
                    return Err(Box::new(InstructionError::MaxSeedLengthExceeded) as Error);
                }
                let seeds_bytes = seeds
                    .iter()
                    .map(|seed| {
                        translate_slice::<u8>(
                            memory_mapping,
                            seed.addr,
                            seed.len,
                            invoke_context.get_check_aligned(),
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                Pubkey::create_program_address(&seeds_bytes, program_id)
                    .map_err(|err| Box::new(SyscallError::BadSeeds(err)) as Error)
            })
            .collect::<Result<Vec<_>, Error>>()?)
    } else {
        Ok(vec![])
    }
}
