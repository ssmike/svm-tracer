use std::mem;

use {
    agave_feature_set::FeatureSet,
    mollusk_svm_error::error::{MolluskError, MolluskPanic},
    mollusk_svm::{Mollusk, result::InstructionResult},
    solana_account::Account,
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_instruction::{AccountMeta, Instruction, error::InstructionError},
    solana_program_runtime::{invoke_context::{EnvironmentConfig, InvokeContext, SerializedAccountMetadata},
    loaded_programs::ProgramCacheEntryOwner, serialization::serialize_parameters, solana_sbpf::{self, declare_builtin_function, memory_region::{MemoryMapping, MemoryRegion}}},
    solana_pubkey::Pubkey,
    solana_transaction_context::{IndexOfAccount, InstructionAccount, InstructionContext, TransactionContext},
    solana_bpf_loader_program::syscalls::{SyscallInvokeSignedC, SyscallInvokeSignedRust},
    std::{cell::RefCell, collections::HashSet, iter::once, rc::Rc},
};

mod syscall_decode;
use mollusk_svm::InvocationInspectCallback;
use syscall_decode::{translate_signers_c, translate_instruction_c, translate_signers_rust, translate_instruction_rust};

// Initial memory layout for an instruction without stack and heap.
#[derive(Debug, Default)]
pub struct AddressSpace {
    pub regions: Vec<MemoryRegion>,
    pub accounts: Vec<SerializedAccountMetadata>,
    mem: Option<solana_sbpf::aligned_memory::AlignedMemory<{solana_sbpf::ebpf::HOST_ALIGN}>>,

    pub text_vmaddr: u64,
    pub text: Vec<u8>,

    pub data_region: MemoryRegion,
    pub data: Vec<u8>,

    // MemoryRegions without backing memory
    stack: MemoryRegion,
    heap: MemoryRegion,
}

impl AddressSpace {
    fn translate_vmaddr(&self, addr: u64, len: u64, load: Option<bool>) -> Option<u64> {
        for r in self.regions.as_slice().iter().chain(vec![&self.stack, &self.heap].into_iter()) {
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
}

#[derive(Debug)]
pub struct TraceEntry {
    pub regs: [u64; 12],
    pub insn: solana_sbpf::ebpf::Insn,

    // mem address. filled only for load/store operations
    pub vaddr: Option<u64>
}

impl TraceEntry {
    fn new(address_space: &AddressSpace, regs: &[u64; 12], move_memory_instruction_classes: bool) -> Self {
        let mut insn = solana_sbpf::ebpf::get_insn_unchecked(address_space.text.as_slice(), regs[11] as usize);
        if insn.opc == solana_sbpf::ebpf::LD_DW_IMM {
            solana_sbpf::ebpf::augment_lddw_unchecked(address_space.text.as_slice(), &mut insn);
        }

        let src = insn.src as usize;
        let dst = insn.dst as usize;

        let mut vaddr: Option<u64> = None;

        let mut fill_memory_access = |vmaddr: u64, len: u64, load: bool|  {
            assert!(address_space.translate_vmaddr(vmaddr, len, Some(load)).is_some());
            vaddr = Some(vmaddr);
        };

        if !move_memory_instruction_classes {
            let src_addr = (regs[src] as i64).wrapping_add(insn.off as i64) as u64;
            let dst_addr = (regs[dst] as i64).wrapping_add(insn.off as i64) as u64;

            match insn.opc {
                solana_sbpf::ebpf::LD_B_REG => fill_memory_access(src_addr, 1, true),
                solana_sbpf::ebpf::LD_H_REG => fill_memory_access(src_addr, 2, true),
                solana_sbpf::ebpf::LD_W_REG => fill_memory_access(src_addr, 4, true),
                solana_sbpf::ebpf::LD_DW_REG => fill_memory_access(src_addr, 8, true),

                // BPF_ST class
                solana_sbpf::ebpf::ST_B_IMM => fill_memory_access(dst_addr, 1, false),
                solana_sbpf::ebpf::ST_H_IMM => fill_memory_access(dst_addr, 2, false),
                solana_sbpf::ebpf::ST_W_IMM => fill_memory_access(dst_addr, 4, false),
                solana_sbpf::ebpf::ST_DW_IMM => fill_memory_access(dst_addr, 8, false),

                // BPF_STX class
                solana_sbpf::ebpf::ST_B_REG => fill_memory_access(dst_addr, 1, false),
                solana_sbpf::ebpf::ST_H_REG => fill_memory_access(dst_addr, 2, false),
                solana_sbpf::ebpf::ST_W_REG => fill_memory_access(dst_addr, 4, false),
                solana_sbpf::ebpf::ST_DW_REG => fill_memory_access(dst_addr, 8, false),

                _ => { }
            }
        };

        if move_memory_instruction_classes {
            let src_addr = (regs[src] as i64).wrapping_add(insn.off as i64) as u64;
            let dst_addr = (regs[dst] as i64).wrapping_add(insn.off as i64) as u64;

            match insn.opc {
                solana_sbpf::ebpf::LD_1B_REG => fill_memory_access(src_addr, 1, false),
                solana_sbpf::ebpf::LD_2B_REG => fill_memory_access(src_addr, 2, false),
                solana_sbpf::ebpf::LD_4B_REG => fill_memory_access(src_addr, 4, false),
                solana_sbpf::ebpf::LD_8B_REG => fill_memory_access(src_addr, 8, false),

                solana_sbpf::ebpf::ST_1B_IMM | solana_sbpf::ebpf::ST_1B_REG => fill_memory_access(dst_addr, 1, true),
                solana_sbpf::ebpf::ST_2B_IMM | solana_sbpf::ebpf::ST_2B_REG => fill_memory_access(dst_addr, 2, true),
                solana_sbpf::ebpf::ST_4B_IMM | solana_sbpf::ebpf::ST_4B_REG => fill_memory_access(dst_addr, 4, true),
                solana_sbpf::ebpf::ST_8B_IMM | solana_sbpf::ebpf::ST_8B_REG => fill_memory_access(dst_addr, 8, true),

                _ => { }
            }
        };

        Self{ 
            regs: *regs,
            insn,
            vaddr
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

        trace.borrow_mut().take().unwrap()
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

                let data = executable.get_ro_region();
                assert!(data.vm_gap_shift == 63, "unexpected gap mode in elf ro region");
                address_space.data = executable.get_ro_section().to_vec();
                data.host_addr.set(address_space.data.as_slice().as_ptr() as u64);
                address_space.data_region = data;

                let heap_size = self.compute_budget.heap_size as u64;
                let stack_size = executable.get_config().stack_size() as u64;

                address_space.heap = MemoryRegion::new_writable(&mut [], solana_sbpf::ebpf::MM_HEAP_START);
                address_space.heap.len = heap_size;
                address_space.heap.vm_addr_end = solana_sbpf::ebpf::MM_HEAP_START.saturating_add(heap_size);


                address_space.stack = MemoryRegion::new_writable_gapped(
                    &mut [],
                    solana_sbpf::ebpf::MM_STACK_START,
                    if !executable.get_sbpf_version().dynamic_stack_frames() && executable.get_config().enable_stack_frame_gaps {
                        stack_size
                    } else {
                        0
                    },
                );
                address_space.stack.len = stack_size;
                address_space.stack.vm_addr_end = solana_sbpf::ebpf::MM_STACK_START.saturating_add(stack_size);

                self.conf.push(InstructionConf{ move_memory_instruction_classes: executable.get_sbpf_version().move_memory_instruction_classes() });
            },
            _ => panic!("{}", MolluskError::ProgramNotCached(&program_id))
        };

        let mut ictx = InstructionContext::default();
        ictx.configure(program_indices.as_slice(), instruction_accounts, &instruction_data);

        let mask_out_rent_epoch_in_vm_serialization = runtime_features.mask_out_rent_epoch_in_vm_serialization;

        let (serialized, regions, accounts_metadata) = serialize_parameters(ctx, &ictx, true, mask_out_rent_epoch_in_vm_serialization)?;
        
        address_space.mem = Some(serialized);
        address_space.regions = regions;
        address_space.accounts = accounts_metadata;

        TRACE_IN_PROGRESS.with(|addr| addr.replace(self as *mut Self));

        Ok(())
    }

    fn add_execution_trace(&mut self, ctx: &InvokeContext) {
        let frame_number = self.pop_frame();
        let trace = ctx.get_traces().last().unwrap();
        self.entries[frame_number] = trace.iter().map(
            |regs| TraceEntry::new(&self.address_space[frame_number], regs,
                    self.conf[frame_number].move_memory_instruction_classes))
            .collect::<Vec<TraceEntry>>();
    }
}
