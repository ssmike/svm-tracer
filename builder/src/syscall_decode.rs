use {
    super::*,
    solana_bpf_loader_program::syscalls::{SyscallError,VmSlice},
    solana_sbpf::memory_region::AccessType,
    solana_stable_layout::stable_instruction::StableInstruction,
    //std::{mem, ptr},
    solana_account_info::AccountInfo,
};

type Error = Box<dyn std::error::Error>;

const MAX_CPI_INSTRUCTION_DATA_LEN: u64 = 10 * 1024;
const MAX_CPI_ACCOUNT_INFOS: u64 = 1024;

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
    check_aligned: bool
) -> Result<StableInstruction, Error> {
    let ix = translate_type::<StableInstruction>(
        memory_mapping,
        addr,
        check_aligned
    )?;
    let account_metas = translate_slice::<AccountMeta>(
        memory_mapping,
        ix.accounts.as_vaddr(),
        ix.accounts.len(),
        check_aligned
    )?;
    let data = translate_slice::<u8>(
        memory_mapping,
        ix.data.as_vaddr(),
        ix.data.len(),
        check_aligned
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
    check_aligned: bool
) -> Result<StableInstruction, Error> {
    let ix_c = translate_type::<SolInstruction>(
        memory_mapping,
        addr,
        check_aligned
    )?;

    let program_id = translate_type::<Pubkey>(
        memory_mapping,
        ix_c.program_id_addr,
        check_aligned
    )?;
    let account_metas = translate_slice::<SolAccountMeta>(
        memory_mapping,
        ix_c.accounts_addr,
        ix_c.accounts_len,
        check_aligned
    )?;
    let data = translate_slice::<u8>(
        memory_mapping,
        ix_c.data_addr,
        ix_c.data_len,
        check_aligned
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
            check_aligned
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
    check_aligned: bool
) -> Result<Vec<Pubkey>, Error> {
    let mut signers = Vec::new();
    if signers_seeds_len > 0 {
        let signers_seeds = translate_slice::<VmSlice<VmSlice<u8>>>(
            memory_mapping,
            signers_seeds_addr,
            signers_seeds_len,
            check_aligned
        )?;
        if signers_seeds.len() > MAX_SIGNERS {
            return Err(Box::new(SyscallError::TooManySigners));
        }
        for signer_seeds in signers_seeds.iter() {
            let untranslated_seeds = translate_slice::<VmSlice<u8>>(
                memory_mapping,
                signer_seeds.ptr(),
                signer_seeds.len(),
                check_aligned
            )?;
            if untranslated_seeds.len() > MAX_SEEDS {
                return Err(Box::new(InstructionError::MaxSeedLengthExceeded));
            }
            let seeds = untranslated_seeds
                .iter()
                .map(|untranslated_seed| {
                    untranslated_seed
                        .translate(memory_mapping, check_aligned)
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
    check_aligned: bool
) -> Result<Vec<Pubkey>, Error> {
    if signers_seeds_len > 0 {
        let signers_seeds = translate_slice::<SolSignerSeedsC>(
            memory_mapping,
            signers_seeds_addr,
            signers_seeds_len,
            check_aligned
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
                    check_aligned
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
                            check_aligned
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

/// Rust representation of C's SolAccountInfo
#[derive(Debug)]
#[repr(C)]
struct SolAccountInfo {
    key_addr: u64,
    lamports_addr: u64,
    data_len: u64,
    data_addr: u64,
    owner_addr: u64,
    rent_epoch: u64,
    is_signer: bool,
    is_writable: bool,
    executable: bool,
}

pub fn make_account_patch_rust<'a>(
    pubkey: Pubkey,
    account_infos_addr: u64,
    account_infos_len: u64,
    regions: &[(Pubkey, VmRegion)],
    memory_mapping: &'a MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<crate::memory::AccountInfoPatch, Error>
{
    make_account_patch::<AccountInfo, ParseRustAccInfo>(
        pubkey,
        account_infos_addr,
        account_infos_len,
        ParseRustAccInfo::default(),
        regions,
        memory_mapping,
        invoke_context)
}

pub fn make_account_patch_c<'a>(
    pubkey: Pubkey,
    account_infos_addr: u64,
    account_infos_len: u64,
    regions: &[(Pubkey, VmRegion)],
    memory_mapping: &'a MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<crate::memory::AccountInfoPatch, Error>
{
    make_account_patch::<SolAccountInfo, ParseSolAccInfo>(
        pubkey,
        account_infos_addr,
        account_infos_len,
        ParseSolAccInfo::default(),
        regions,
        memory_mapping,
        invoke_context)
}

pub struct VmRegion {
    start: u64,
    len: u64
}

trait ParseAccInfo {
    type Info;

    fn key_addr(info: &Self::Info) -> u64;

    fn lamports(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Patch<u64>, Error>;

    fn owner(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Patch<Pubkey>, Error>;

    fn data_region_start(info: &Self::Info, vmaddr: u64) -> Result<Option<Patch<u64>>, Error>;

    fn data_region_len(info: &Self::Info, vmaddr: u64) -> Result<Option<Patch<u64>>, Error>;

    fn data_region_repr(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Option<Patch<[u64; 2]>>, Error>;

    fn data_region(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<VmRegion, Error>;
}

#[derive(Default)]
struct ParseRustAccInfo<'a> {
    marker: std::marker::PhantomData<AccountInfo<'a>>
}

impl<'a> ParseAccInfo for ParseRustAccInfo<'a> {
    type Info = AccountInfo<'a>;

    fn key_addr(info: &Self::Info) -> u64 {
        info.key as *const _ as u64
    }

    fn lamports(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Patch<u64>, Error> {
        let vmaddr = info.lamports.as_ptr() as u64;
        let vmaddr = *translate_type::<u64>(memory_mapping, vmaddr, check_aligned)?;
        Ok(Patch{ vmaddr, val: *translate_type::<u64>(memory_mapping, vmaddr, check_aligned)? })
    }

    fn owner(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Patch<Pubkey>, Error> {
        let vmaddr = info.owner as *const _ as u64;
        Ok(Patch { vmaddr, val: *translate_type(memory_mapping, vmaddr, check_aligned)? })
    }

    fn data_region_len(_: &Self::Info, _: u64) -> Result<Option<Patch<u64>>, Error> {
        Ok(None)
    }

    fn data_region_start(_: &Self::Info, _: u64) -> Result<Option<Patch<u64>>, Error> {
        Ok(None)
    }

    fn data_region_repr(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Option<Patch<[u64; 2]>>, Error> {
        let data_ptr = info.data.as_ptr() as *const _ as u64;
        let data = translate_type::<&[u8]>(
            memory_mapping,
            info.data.as_ptr() as *const _ as u64,
            check_aligned
        )?;
        Ok(Some(Patch {vmaddr: data_ptr as u64, val: unsafe { std::mem::transmute(*data)} }))
    }

    fn data_region(account_info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<VmRegion, Error> {
        let data = *translate_type::<&[u8]>(
            memory_mapping,
            account_info.data.as_ptr() as *const _ as u64,
            check_aligned
        )?;

        Ok(VmRegion {
            start: data.as_ptr() as u64,
            len: data.len() as u64
        })
    }
}

#[derive(Default)]
struct ParseSolAccInfo {}

impl ParseAccInfo for ParseSolAccInfo {
    type Info = SolAccountInfo;

    fn key_addr(info: &Self::Info) -> u64 {
        info.key_addr
    }

    fn lamports(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Patch<u64>, Error> {
        let vmaddr = info.lamports_addr;
        Ok(Patch{ vmaddr, val: *translate_type::<u64>(memory_mapping, vmaddr, check_aligned)? })
    }

    fn owner(info: &Self::Info, memory_mapping: &MemoryMapping, check_aligned: bool) -> Result<Patch<Pubkey>, Error> {
        let vmaddr = info.owner_addr;
        Ok(Patch{ vmaddr, val: *translate_type::<Pubkey>(memory_mapping, vmaddr, check_aligned)? })
    }

    fn data_region_repr(_: &Self::Info, _: &MemoryMapping, _: bool) -> Result<Option<Patch<[u64; 2]>>, Error> {
        Ok(None)
    }

    fn data_region_start(info: &Self::Info, vm_addr: u64) -> Result<Option<Patch<u64>>, Error> {
        let vmaddr = vm_addr.saturating_add(std::mem::offset_of!(Self::Info, data_addr) as u64);
        Ok(Some(Patch{vmaddr, val: info.data_addr as u64}))

    }

    fn data_region_len(info: &Self::Info, vmaddr: u64) -> Result<Option<Patch<u64>>, Error> {
        let vmaddr = vmaddr.saturating_add(std::mem::offset_of!(Self::Info, data_len) as u64);
        Ok(Some(Patch{vmaddr, val: info.data_len }))
    }

    fn data_region(info: &Self::Info, _: &MemoryMapping, _: bool) -> Result<VmRegion, Error> {
        Ok(VmRegion { start: info.data_addr, len: info.data_len })
    }
}

fn make_account_patch<'a, T, Parse>(
    pubkey: Pubkey,
    account_infos_addr: u64,
    account_infos_len: u64,
    _: Parse,
    regions: &[(Pubkey, VmRegion)],
    memory_mapping: &'a MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<crate::memory::AccountInfoPatch, Error>
where
    Parse: ParseAccInfo
{
    let (infos, keys) = translate_account_infos(
        account_infos_addr,
        account_infos_len,
        Parse::key_addr,
        memory_mapping,
        invoke_context)?;

    let check_aligned = invoke_context.get_check_aligned();
    
    assert!(account_infos_len as usize == regions.len());

    for i in 0..account_infos_len {
        let i = i as usize;
        let (key, region_before) = &regions[i];
        if pubkey == *key {
            assert!(pubkey == *keys[i]);
            let info = &infos[i];
            let vmaddr = account_infos_addr.saturating_add(
                i.saturating_mul(mem::size_of::<T>()) as u64);

            let region_after = Parse::data_region(info, memory_mapping, check_aligned)?;
            assert!(region_before.start == region_after.start);
            let mut mem = translate_slice::<u8>(memory_mapping, region_after.start, region_after.len, check_aligned)?.to_vec();
            if region_after.len < region_before.len {
                mem.extend(std::iter::repeat_n(0_u8, (region_before.len - region_after.len) as usize));
            }

            return Ok(crate::memory::AccountInfoPatch {
                lamports_patch: Parse::lamports(info, memory_mapping, check_aligned)?,
                owner_patch: Parse::owner(info, memory_mapping, check_aligned)?,
                data_slice_patch: Parse::data_region_repr(info, memory_mapping, check_aligned)?,
                data_len_patch: Parse::data_region_len(info, vmaddr)?,
                data_ptr_patch: Parse::data_region_start(info, vmaddr)?,
                mem_region_patch: MemRegionPatch {vmaddr: region_after.start, mem}
            })
        }
    }

    panic!("unmatched pubkey in cpi call")
}

pub fn translate_regions_rust<'a>(
    account_infos_addr: u64,
    account_infos_len: u64,
    memory_mapping: &'a MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<Vec<(Pubkey, VmRegion)>, Error>
{
    translate_regions::<AccountInfo, ParseRustAccInfo>(
        account_infos_addr,
        account_infos_len,
        ParseRustAccInfo::default(),
        memory_mapping,
        invoke_context)
}

pub fn translate_regions_c<'a>(
    account_infos_addr: u64,
    account_infos_len: u64,
    memory_mapping: &'a MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<Vec<(Pubkey, VmRegion)>, Error>
{
    translate_regions::<SolAccountInfo, ParseSolAccInfo>(
        account_infos_addr,
        account_infos_len,
        ParseSolAccInfo::default(),
        memory_mapping,
        invoke_context)
}

fn translate_regions<'a, T, Parse>(
    account_infos_addr: u64,
    account_infos_len: u64,
    _: Parse,
    memory_mapping: &'a MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<Vec<(Pubkey, VmRegion)>, Error>
where
    Parse: ParseAccInfo
{
    let (infos, keys) = translate_account_infos(
        account_infos_addr,
        account_infos_len,
        Parse::key_addr,
        memory_mapping,
        invoke_context)?;

    let check_aligned = invoke_context.get_check_aligned();
    let mut regions = Vec::<(Pubkey, VmRegion)>::new();
    for i in 0..account_infos_len {
        let i = i as usize;
        regions.push((*keys[i], Parse::data_region(&infos[i], memory_mapping, check_aligned)?));
    }

    Ok(regions)
}

fn translate_account_infos<'a, T, F>(
    account_infos_addr: u64,
    account_infos_len: u64,
    key_addr: F,
    memory_mapping: &'a MemoryMapping,
    invoke_context: &mut InvokeContext,
) -> Result<(&'a [T], Vec<&'a Pubkey>), Error>
where
    F: Fn(&T) -> u64,
{
    let direct_mapping = invoke_context
        .get_feature_set()
        .bpf_account_data_direct_mapping;
    let check_aligned = invoke_context.get_check_aligned();

    // In the same vein as the other check_account_info_pointer() checks, we don't lock
    // this pointer to a specific address but we don't want it to be inside accounts, or
    // callees might be able to write to the pointed memory.
    if direct_mapping
        && account_infos_addr
            .saturating_add(account_infos_len.saturating_mul(std::mem::size_of::<T>() as u64))
            >= solana_sbpf::ebpf::MM_INPUT_START
    {
        return Err(SyscallError::InvalidPointer.into());
    }

    let account_infos = translate_slice::<T>(
        memory_mapping,
        account_infos_addr,
        account_infos_len,
        check_aligned
    )?;
    if account_infos_len > MAX_CPI_ACCOUNT_INFOS {
        return Err(Box::new(SyscallError::TooManyAccounts));
    }
    let mut account_info_keys = Vec::with_capacity(account_infos_len as usize);
    #[allow(clippy::needless_range_loop)]
    for account_index in 0..account_infos_len as usize {
        #[allow(clippy::indexing_slicing)]
        let account_info = &account_infos[account_index];
        account_info_keys.push(translate_type::<Pubkey>(
            memory_mapping,
            key_addr(account_info),
            check_aligned
        )?);
    }
    Ok((account_infos, account_info_keys))
}
