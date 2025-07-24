use std::{alloc::alloc_zeroed, error::Error, mem};

use {
    agave_feature_set::FeatureSet,
    mollusk_svm_error::error::{MolluskError, MolluskPanic},
    mollusk_svm::{Mollusk, result::InstructionResult},
    solana_account::Account,
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_instruction::{AccountMeta, Instruction, error::InstructionError},
    solana_program_runtime::{invoke_context::{InvokeContext, SerializedAccountMetadata},
    loaded_programs::ProgramCacheEntryOwner, serialization::serialize_parameters, solana_sbpf::{self, declare_builtin_function, memory_region::{MemoryMapping, MemoryRegion}}},
    solana_pubkey::Pubkey,
    solana_transaction_context::{InstructionAccount, InstructionContext},
    solana_bpf_loader_program::syscalls::{SyscallInvokeSignedC, SyscallInvokeSignedRust},
    std::{cell::RefCell, rc::Rc},
};

mod syscall_decode;
use mollusk_svm::InvocationInspectCallback;
use solana_program_runtime::solana_sbpf::{aligned_memory::{AlignedMemory, Pod}, program::BuiltinProgram};
use syscall_decode::{translate_signers_c, translate_instruction_c, translate_signers_rust, translate_instruction_rust};


// Initial memory layout for an instruction without stack and heap.
#[derive(Debug, Default)]
pub struct AddressSpace {
    pub regions: Vec<MemoryRegion>,
    pub accounts: Vec<SerializedAccountMetadata>,
    mem: Vec<AlignedMemory<{solana_sbpf::ebpf::HOST_ALIGN}>>,

    pub text_vmaddr: u64,
    pub text: Vec<u8>,
}

impl AddressSpace {
    fn translate_vmaddr(&self, addr: u64, len: u64, load: Option<bool>) -> Option<u64> {
        for r in self.regions.as_slice().iter() {
            if let Some(addr) = r.vm_to_host(addr, len) {
                return match load {
                    Some(true) => Some(addr),
                    None => Some(addr),
                    Some(false) => { if !r.writable.get() { None } else { Some(addr) } }
                };
            }
        }
        None
    }

    pub fn replay(&mut self, op: MemoryAccess) {
        match op {
            MemoryAccess::Write{value, vmaddr, size, ..} => {
                let phy_addr = self.translate_vmaddr(vmaddr, size as u64, Some(false)).unwrap();
                macro_rules! perform_write {
                    ($ty:ty) => {
                        unsafe {
                            std::ptr::write_unaligned(phy_addr as *mut $ty, value as $ty);
                        }
                    }
                }
                match size {
                    1 => perform_write!(u8),
                    2 => perform_write!(u16),
                    4 => perform_write!(u32),
                    8 => perform_write!(u64),
                    _ => {}
                }
            },
            _ => {}
        };
    }
}

impl Clone for AddressSpace {
    fn clone(&self) -> Self {
        let mut regions: Vec<MemoryRegion> = vec![];
        let mem = self.mem.clone();

        for region in regions.as_mut_slice() {
            let mut regions_found = 0;
            for i in 0..mem.len() {
                let slice = self.mem[i].as_slice();
                let start = slice.as_ptr() as u64;
                let size = slice.len() as u64;
                let addr = region.host_addr.get();
                if start <= addr && addr <= start + size {
                    region.host_addr.set(mem[i].as_slice().as_ptr() as u64);
                    regions_found += 1;
                }
            }
            assert!(regions_found == 1);
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

#[derive(Debug)]
pub enum Syscall {
}

#[derive(Debug)]
pub struct TraceEntry {
    pub regs_after: [u64; 12],
    pub regs_before: [u64; 12],
    pub insn: solana_sbpf::ebpf::Insn,

    pub mem: Option<MemoryAccess>,
    pub syscall: Option<Syscall>,
}

impl TraceEntry {
    #[inline]
    fn load<T: Pod + Into<u64>>(&self, phy_addr: u64) -> u64 {
        unsafe { std::ptr::read_unaligned::<T>(phy_addr as *const _) }.into()
    }

    fn fill_memory_access(&mut self, next: &Self, address_space: &AddressSpace, move_memory_instruction_classes: bool) {
        self.regs_after = next.regs_before;

        let src = self.insn.src as usize;
        let dst = self.insn.dst as usize;

        let mut mem: Option<MemoryAccess> = None;

        macro_rules! fill_mem_read {
            ($vmaddr:ident, $typ:ty, $value:expr) => {
                {
                    let len = std::mem::size_of::<$typ>();
                    let phy_addr = address_space.translate_vmaddr($vmaddr, len as u64, Some(true)).unwrap();
                    let value = $value as $typ as u64;
                    mem = Some(MemoryAccess::Read{size: len as u8, value, vmaddr:$vmaddr});
                    assert!(self.load::<$typ>(phy_addr) == value);
                }
            }
        }
        macro_rules! fill_mem_write {
            ($vmaddr:ident, $typ:ty, $value:expr) => {
                {
                    let len = std::mem::size_of::<$typ>() as u8;
                    let phy_addr = address_space.translate_vmaddr($vmaddr, len as u64, Some(false)).unwrap();
                    let value = $value as $typ as u64;
                    let before = self.load::<$typ>(phy_addr);
                    mem = Some(MemoryAccess::Write { size: len, vmaddr: $vmaddr, before, value });
                }
            }
        }

        if !move_memory_instruction_classes {
            let src_addr = (self.regs_before[src] as i64).wrapping_add(self.insn.off as i64) as u64;
            let dst_addr = (self.regs_before[dst] as i64).wrapping_add(self.insn.off as i64) as u64;

            match self.insn.opc {
                solana_sbpf::ebpf::LD_B_REG => fill_mem_read!(src_addr, u8, self.regs_after[dst]),
                solana_sbpf::ebpf::LD_H_REG => fill_mem_read!(src_addr, u16, self.regs_after[dst]),
                solana_sbpf::ebpf::LD_W_REG => fill_mem_read!(src_addr, u32, self.regs_after[dst]),
                solana_sbpf::ebpf::LD_DW_REG => fill_mem_read!(src_addr, u64, self.regs_after[dst]),

                // BPF_ST class
                solana_sbpf::ebpf::ST_B_IMM => fill_mem_write!(dst_addr, u8, self.insn.imm),
                solana_sbpf::ebpf::ST_H_IMM => fill_mem_write!(dst_addr, u16, self.insn.imm),
                solana_sbpf::ebpf::ST_W_IMM => fill_mem_write!(dst_addr, u32, self.insn.imm),
                solana_sbpf::ebpf::ST_DW_IMM => fill_mem_write!(dst_addr, u64, self.insn.imm),

                // BPF_STX class
                solana_sbpf::ebpf::ST_B_REG => fill_mem_write!(dst_addr, u8, self.regs_before[src]),
                solana_sbpf::ebpf::ST_H_REG => fill_mem_write!(dst_addr, u16, self.regs_before[src]),
                solana_sbpf::ebpf::ST_W_REG => fill_mem_write!(dst_addr, u32, self.regs_before[src]),
                solana_sbpf::ebpf::ST_DW_REG => fill_mem_write!(dst_addr, u64, self.regs_before[src]),

                _ => { }
            }
        };

        if move_memory_instruction_classes {
            let src_addr = (self.regs_before[src] as i64).wrapping_add(self.insn.off as i64) as u64;
            let dst_addr = (self.regs_before[dst] as i64).wrapping_add(self.insn.off as i64) as u64;

            match self.insn.opc {
                solana_sbpf::ebpf::LD_1B_REG => fill_mem_read!(src_addr, u8, self.regs_after[dst]),
                solana_sbpf::ebpf::LD_2B_REG => fill_mem_read!(src_addr, u16, self.regs_after[dst]),
                solana_sbpf::ebpf::LD_4B_REG => fill_mem_read!(src_addr, u32, self.regs_after[dst]),
                solana_sbpf::ebpf::LD_8B_REG => fill_mem_read!(src_addr, u64, self.regs_after[dst]),

                solana_sbpf::ebpf::ST_1B_IMM => fill_mem_write!(dst_addr, u8, self.insn.imm),
                solana_sbpf::ebpf::ST_1B_REG => fill_mem_write!(dst_addr, u8, self.regs_before[src]),
                solana_sbpf::ebpf::ST_2B_IMM => fill_mem_write!(dst_addr, u16, self.insn.imm),
                solana_sbpf::ebpf::ST_2B_REG => fill_mem_write!(dst_addr, u16, self.regs_before[src]),
                solana_sbpf::ebpf::ST_4B_IMM => fill_mem_write!(dst_addr, u16, self.insn.imm),
                solana_sbpf::ebpf::ST_4B_REG => fill_mem_write!(dst_addr, u32, self.regs_before[src]),
                solana_sbpf::ebpf::ST_8B_IMM => fill_mem_write!(dst_addr, u64, self.insn.imm),
                solana_sbpf::ebpf::ST_8B_REG => fill_mem_write!(dst_addr, u64, self.regs_before[src]),

                _ => { }
            }
        };

        self.mem = mem;
    }

    fn new(regs: &[u64; 12], address_space: &AddressSpace) -> Self {
        let mut insn = solana_sbpf::ebpf::get_insn_unchecked(address_space.text.as_slice(), regs[11] as usize);
        if insn.opc == solana_sbpf::ebpf::LD_DW_IMM {
            solana_sbpf::ebpf::augment_lddw_unchecked(address_space.text.as_slice(), &mut insn);
        }


        Self { 
            regs_before: *regs,
            regs_after: *regs,
            insn,
            mem: None,
            syscall: None
        }
    }
}

#[derive(Debug, Default)]
pub struct InstructionConf {
    move_memory_instruction_classes: bool
}

#[derive(Debug)]
pub struct InstructionTrace {
    pub entries: Vec<Vec<TraceEntry>>,
    pub address_space: Vec<AddressSpace>,
    pub result: InstructionResult,
    pub conf: Vec<InstructionConf>,

    frame_number: Vec<usize>,

    feature_set: FeatureSet,
    compute_budget: ComputeBudget
}

pub struct InstructionTraceBuilder {
    trace: Rc<RefCell<Option<InstructionTrace>>>
}

impl InstructionTraceBuilder {
    // prepares programs environment for tracing and returns an old env
    pub fn prepare_for_tracing(mollusk: &mut Mollusk) -> BuiltinProgram<InvokeContext<'static>> {
        let (env, old_env) = {
            let mut config = mollusk.program_cache.program_runtime_environment.get_config().clone();
            let old_config = config.clone();
            let mut old_loader = BuiltinProgram::new_loader(old_config);

            config.enable_instruction_tracing = true;
            let mut loader = BuiltinProgram::new_loader(config);

            for (_key, (name, value)) in mollusk
                .program_cache
                .program_runtime_environment
                .get_function_registry()
                .iter()
            {
                let name = std::str::from_utf8(name).unwrap();
                old_loader.register_function(name, value).unwrap();
                match name {
                    "sol_invoke_signed_c" => loader.register_function(name, SyscallInvokeSignedCStub::vm),
                    "sol_invoke_signed_rust" => loader.register_function(name, SyscallInvokeSignedRustStub::vm),
                    _ => loader.register_function(name, value)
                }.unwrap();
            }

            (loader, old_loader)
        };

        mollusk.program_cache.program_runtime_environment = env;

        old_env
    }

    pub fn build(mollusk: &mut Mollusk, instruction: &Instruction, accounts: &[(Pubkey, Account)]) -> InstructionTrace {
        let this = Self {
            trace: RefCell::new(Some(InstructionTrace::default())).into()
        };
        let trace = this.trace.clone();

        this.trace.borrow_mut().as_mut().unwrap().configure(mollusk);

        let mut cb: Box<dyn InvocationInspectCallback> = Box::new(this);

        mem::swap(&mut cb, &mut mollusk.invocation_inspect_callback);
        let result = mollusk.process_instruction(instruction, accounts);
        trace.borrow_mut().as_mut().unwrap().result.absorb(result);

        let result = trace.borrow_mut().take().unwrap();
        result
    }
}

impl mollusk_svm::InvocationInspectCallback for InstructionTraceBuilder {
    fn before_invocation(
            &self,
            program_id: &Pubkey,
            instruction_data: &[u8],
            instruction_accounts: &[InstructionAccount],
            invoke_context: &InvokeContext,
        ) {
        self.trace.borrow_mut().as_mut().unwrap().prepare(program_id, instruction_data, instruction_accounts, invoke_context).unwrap();
    }

    fn after_invocation(&self, invoke_context: &InvokeContext) {
        self.trace.borrow_mut().as_mut().unwrap().add_execution_trace(invoke_context);
    }
}

thread_local! {
    static TRACE_IN_PROGRESS: RefCell<*mut InstructionTrace> = RefCell::new(std::ptr::null_mut());
}

macro_rules! instr_syscall_stub {
    ($name:ident, $syscall:ident, $translate_instruction:ident, $translate_signers:ident) => {
        declare_builtin_function!(
            $name,
            fn rust(
                invoke_context: &mut InvokeContext,
                instruction_addr: u64,
                account_infos_addr: u64,
                account_infos_len: u64,
                signers_seeds_addr: u64,
                signers_seeds_len: u64,
                memory_mapping: &mut MemoryMapping,
            ) -> Result<u64, Box<dyn std::error::Error>> {
                let instruction = $translate_instruction(instruction_addr, memory_mapping, invoke_context)?;

                let transaction_context = &invoke_context.transaction_context;
                let instruction_context = transaction_context.get_current_instruction_context()?;
                let caller_program_id = instruction_context.get_last_program_key(transaction_context)?;

                let signers = $translate_signers(
                    caller_program_id,
                    signers_seeds_addr,
                    signers_seeds_len,
                    memory_mapping,
                    invoke_context,
                )?;
                let (instruction_accounts, _) =
                    invoke_context.prepare_instruction(&instruction, &signers)?;

                TRACE_IN_PROGRESS.with_borrow_mut(|trace| {
                    let trace: &mut InstructionTrace = unsafe{&mut (**trace)};
                    trace.prepare(
                        &instruction.program_id,
                        instruction.data.as_ref(),
                        &instruction_accounts,
                        invoke_context)
                })?;

                let result = $syscall::rust(
                    invoke_context,
                    instruction_addr,
                    account_infos_addr,
                    account_infos_len,
                    signers_seeds_addr,
                    signers_seeds_len,
                    memory_mapping);

                TRACE_IN_PROGRESS.with_borrow_mut(|trace| {
                    let trace: &mut InstructionTrace = unsafe{&mut (**trace)};
                    trace.add_execution_trace(invoke_context);
                });

                result
            }
        );
        
    };
}

instr_syscall_stub!(SyscallInvokeSignedCStub, SyscallInvokeSignedC, translate_instruction_c, translate_signers_c);
instr_syscall_stub!(SyscallInvokeSignedRustStub, SyscallInvokeSignedRust, translate_instruction_rust, translate_signers_rust);

impl Default for InstructionTrace {
    fn default() -> Self {
        Self {
            entries: vec![],
            result: InstructionResult::default(),
            address_space: vec![],
            conf: vec![],
            frame_number: vec![],
            feature_set: FeatureSet::default(),
            compute_budget: ComputeBudget::default()
        }
    }
}

impl InstructionTrace {
    fn configure(&mut self, mollusk: &Mollusk) {
        self.feature_set = mollusk.feature_set.clone();
        self.compute_budget = mollusk.compute_budget.clone();
    }

    fn push_frame(&mut self) {
        let frame_number = self.address_space.len();
        self.entries.push(vec![]);
        self.frame_number.push(frame_number);

        self.address_space.push(AddressSpace::default());
    }

    fn pop_frame(&mut self) -> usize {
        self.frame_number.pop().unwrap()
    }
 
    fn prepare(&mut self,
        program_id: &Pubkey,
        instruction_data: &[u8],
        instruction_accounts: &[InstructionAccount],
        invoke_context: &InvokeContext) -> Result<(), InstructionError>
    {

        let program_indices = vec![invoke_context.transaction_context.find_index_of_account(program_id).unwrap()];

        let cache = &invoke_context.program_cache_for_tx_batch;
        let ctx = &invoke_context.transaction_context;

        let cache_entry = cache.find(&program_id).or_panic_with(MolluskError::ProgramNotCached(&program_id));
        let cache_entry_type = &cache_entry.program;
        match cache_entry.account_owner {
            ProgramCacheEntryOwner::LoaderV1
                | ProgramCacheEntryOwner::LoaderV2
                | ProgramCacheEntryOwner::LoaderV3
                | ProgramCacheEntryOwner::LoaderV4 => {}
            _ => return Err(InstructionError::UnsupportedProgramId)
        }

        let runtime_features = self.feature_set.runtime_features();

        self.push_frame();
        let address_space = self.address_space.last_mut().unwrap();

        match cache_entry_type  {
            solana_program_runtime::loaded_programs::ProgramCacheEntryType::Loaded(executable) => {

                let (vmaddr, text) = executable.get_text_bytes();
                address_space.text_vmaddr = vmaddr;
                address_space.text = text.to_vec();

                let ro_mem_region = executable.get_ro_region();
                assert!(ro_mem_region.vm_gap_shift == 63, "unexpected gap mode in elf ro region");
                let ro_mem = AlignedMemory::<{solana_sbpf::ebpf::HOST_ALIGN}>::from_slice(executable.get_ro_section());

                // as we copied ro memory it should start in the same vmaddr
                ro_mem_region.host_addr.set(ro_mem.as_slice().as_ptr() as u64);
                address_space.mem.push(ro_mem);
                address_space.regions.push(ro_mem_region);

                let heap_size = self.compute_budget.heap_size as usize;
                let stack_size = executable.get_config().stack_size() as usize;

                // heap memory
                let mut heap_memory = AlignedMemory::<{solana_sbpf::ebpf::HOST_ALIGN}>::with_capacity_zeroed(heap_size);
                address_space.regions.push(MemoryRegion::new_writable(heap_memory.as_slice_mut(), solana_sbpf::ebpf::MM_HEAP_START));
                address_space.mem.push(heap_memory);
                //address_space.heap = MemoryRegion::new_writable(&mut [], solana_sbpf::ebpf::MM_HEAP_START);
                //address_space.heap.len = heap_size;
                //address_space.heap.vm_addr_end = solana_sbpf::ebpf::MM_HEAP_START.saturating_add(heap_size);

                // stack memory
                let mut stack_memory = AlignedMemory::<{solana_sbpf::ebpf::HOST_ALIGN}>::with_capacity_zeroed(stack_size);
                address_space.regions.push(
                    MemoryRegion::new_writable_gapped(
                        stack_memory.as_slice_mut(),
                        solana_sbpf::ebpf::MM_STACK_START,
                        if !executable.get_sbpf_version().dynamic_stack_frames() && executable.get_config().enable_stack_frame_gaps {
                            stack_size as u64
                        } else {
                            0
                        },
                    )
                );
                address_space.mem.push(stack_memory);
                //address_space.stack = MemoryRegion::new_writable_gapped(
                //    &mut [],
                //    solana_sbpf::ebpf::MM_STACK_START,
                //    if !executable.get_sbpf_version().dynamic_stack_frames() && executable.get_config().enable_stack_frame_gaps {
                //        stack_size
                //    } else {
                //        0
                //    },
                //);
                //address_space.stack.len = stack_size;
                //address_space.stack.vm_addr_end = solana_sbpf::ebpf::MM_STACK_START.saturating_add(stack_size);

                self.conf.push(InstructionConf{ move_memory_instruction_classes: executable.get_sbpf_version().move_memory_instruction_classes() });
            },
            _ => panic!("{}", MolluskError::ProgramNotCached(&program_id))
        };

        let mut ictx = InstructionContext::default();
        ictx.configure(program_indices.as_slice(), instruction_accounts, &instruction_data);

        let mask_out_rent_epoch_in_vm_serialization = runtime_features.mask_out_rent_epoch_in_vm_serialization;

        let (serialized, regions, accounts_metadata) = serialize_parameters(ctx, &ictx, true, mask_out_rent_epoch_in_vm_serialization)?;
        
        address_space.mem.push(serialized);
        address_space.regions = regions;
        address_space.accounts = accounts_metadata;

        TRACE_IN_PROGRESS.with(|addr| addr.replace(self as *mut Self));

        Ok(())
    }

    fn add_execution_trace(&mut self, ctx: &InvokeContext) {
        let frame_number = self.pop_frame();
        let trace = ctx.get_traces().last().unwrap();
        self.entries[frame_number] = trace.iter().map(
            |regs| TraceEntry::new(regs, &self.address_space[frame_number]))
                .collect::<Vec<TraceEntry>>();
        let slice = &mut self.entries[frame_number];
        let mut address_space = self.address_space[frame_number].clone();
        for i in 0..slice.len() {
            {
                let slice = &mut slice[i..i+2];
                let (fs, sc) = slice.split_at_mut(1);
                if !sc.is_empty() && !fs.is_empty() {
                    fs[0].fill_memory_access(&sc[0], &address_space, self.conf[frame_number].move_memory_instruction_classes);
                }
            }
            if let Some(op@MemoryAccess::Write {..}) = &slice[i].mem {
                address_space.replay(op.clone())
            }
        }
    }
}
