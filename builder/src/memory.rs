use crate::error::EmulationError;
use solana_program_runtime::{solana_sbpf::{ebpf::HOST_ALIGN, aligned_memory::{Pod, AlignedMemory}, memory_region::MemoryRegion}, invoke_context::SerializedAccountMetadata};
use solana_pubkey::Pubkey;

#[derive(Debug, Default)]
pub struct AddressSpace {
    pub regions: Vec<MemoryRegion>,
    pub accounts: Vec<SerializedAccountMetadata>,
    pub(crate) mem: Vec<AlignedMemory<{HOST_ALIGN}>>,

    pub text_vmaddr: u64,
    pub text: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum MemoryAccess {
    Read{
        size: u8,
        vmaddr: u64,
        value: u64,
    },
    Write{
        size: u8,
        vmaddr: u64,
        before: u64,
        value: u64
    }
}

#[derive(Debug, Clone)]
pub struct Patch<T> {
    pub vmaddr: u64,
    pub val: T
}

pub struct AccountInfoPatch {
    pub key: Pubkey,
    pub lamports_patch: Patch<u64>,
    pub owner_patch: Patch<Pubkey>,
    pub data_lent_patch: Patch<u64>,
}

impl AddressSpace {
    fn translate_vmaddr(&self, addr: u64, len: u64, load: Option<bool>) -> Result<u64, EmulationError> {
        for r in self.regions.as_slice().iter().rev() {
            if let Some(addr) = r.vm_to_host(addr, len) {
                return match load {
                    Some(true) => Ok(addr),
                    None => Ok(addr),
                    Some(false) => { if !r.writable.get() { Err(EmulationError::AddressTranslationError { vmaddr: addr }) } else { Ok(addr) } }
                };
            }
        }

        Err(EmulationError::AddressTranslationError { vmaddr: addr })
    }

    #[inline]
    fn mload<T: Pod + Into<u64>>(phy_addr: u64) -> u64 {
        unsafe { std::ptr::read_unaligned::<T>(phy_addr as *const _) }.into()
    }

    #[inline]
    fn mstore<T: Pod>(phy_addr: u64, value: T) {
        unsafe { std::ptr::write_unaligned::<T>(phy_addr as *mut T, value) }.into()
    }

    #[inline]
    pub fn load<T: Pod + Into<u64>>(&self, vmaddr: u64) -> Result<u64, EmulationError> {
        let phy_addr = self.translate_vmaddr(vmaddr, std::mem::size_of::<T>() as u64, Some(true))?;
        Ok(Self::mload::<T>(phy_addr))
    }

    #[inline]
    pub fn store<T: Pod>(&mut self, vmaddr: u64, value: T) -> Result<(), EmulationError> {
        let phy_addr = self.translate_vmaddr(vmaddr, std::mem::size_of::<T>() as u64, Some(false))?;
        Ok(Self::mstore(phy_addr, value))
    }

    pub fn replay(&mut self, op: MemoryAccess) -> Result<(), EmulationError> {
        match op {
            MemoryAccess::Write{value, vmaddr, size, ..} => {
                let phy_addr = self.translate_vmaddr(vmaddr, size as u64, Some(false))?;
                match size {
                    1 => Self::mstore(phy_addr, value as u8),
                    2 => Self::mstore(phy_addr, value as u16),
                    4 => Self::mstore(phy_addr, value as u32),
                    8 => Self::mstore(phy_addr, value as u64),
                    _ => {}
                }
            },
            _ => {}
        };

        Ok(())
    }
}

impl Clone for AddressSpace {
    fn clone(&self) -> Self {
        let mut regions: Vec<MemoryRegion> = vec![];
        let mem = self.mem.clone();

        for region in self.regions.as_slice() {
            let mut regions_found = 0;
            let mut host_addr: u64 = 0;
            for i in 0..mem.len() {
                let slice = self.mem[i].as_slice();
                let start = slice.as_ptr() as u64;
                let size = slice.len() as u64;
                let addr = region.host_addr.get();
                if start <= addr && addr <= start + size {
                    host_addr = mem[i].as_slice().as_ptr() as u64;
                    regions_found += 1;
                }
            }
            assert!(regions_found == 1);
            regions.push(MemoryRegion {
                host_addr: host_addr.into(),
                vm_addr: region.vm_addr,
                vm_addr_end: region.vm_addr_end,
                len: region.len,
                vm_gap_shift: region.vm_gap_shift,
                writable: region.writable.clone(),
                cow_callback_payload: region.cow_callback_payload
            });
        }

        Self {
            regions,
            mem,
            accounts: self.accounts.clone(),
            text: self.text.clone(),
            text_vmaddr: self.text_vmaddr
        }
    }
}
