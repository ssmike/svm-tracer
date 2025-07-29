use std::{alloc::alloc_zeroed, cell::Cell, collections::BTreeMap, error::Error, mem};

use {
    agave_feature_set::FeatureSet,
    mollusk_svm_error::error::{MolluskError, MolluskPanic},
    mollusk_svm::{Mollusk, result::InstructionResult, InvocationInspectCallback},
    solana_account::Account,
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_instruction::{AccountMeta, Instruction, error::InstructionError},
    solana_program_runtime::{solana_sbpf::{aligned_memory::AlignedMemory, program::BuiltinProgram}, invoke_context::InvokeContext,
    loaded_programs::ProgramCacheEntryOwner, serialization::serialize_parameters, solana_sbpf::{self, declare_builtin_function, memory_region::{MemoryMapping, MemoryRegion}}},
    solana_pubkey::Pubkey,
    solana_transaction_context::{InstructionAccount, InstructionContext},
    solana_bpf_loader_program::{calculate_heap_cost, syscalls::{SyscallInvokeSignedC, SyscallInvokeSignedRust}},
    std::{cell::RefCell, rc::Rc, borrow::Borrow},
    log::{debug,error},
    solana_compute_budget::compute_budget::SVMTransactionExecutionCost
};

pub mod error;
use error::EmulationError;

pub mod memory;
use memory::*;

mod syscall_decode;

#[derive(Debug, Clone)]
pub enum CPIKind {
    C, Rust
}

#[derive(Debug, Clone)]
pub struct CPIEntry {
    pub program: Pubkey,
    pub instruction_data: Vec<u8>,
    pub instruction_accounts: Vec<InstructionAccount>,
    pub return_data: Vec<u8>,
    pub kind: CPIKind,

    pub callee_frame: usize,
    pub caller_frame: usize,

    pub cu_meter_before: CuMeter,
    pub cu_meter_after: CuMeter,

    pub acc_patches: Vec<(Pubkey, AccountInfoPatch)>,
}

#[derive(Debug, Clone)]
pub enum SysCall {
    MemCpy{dst: u64, src: u64, n: u64},
    MemCmp{s1: u64, s2: u64, n: u64, result: u64},
    CPI(CPIEntry),
    Unknown(String)
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct CuMeter(u64);

#[derive(Debug, Clone)]
pub struct TraceEntry {
    pub regs_after: [u64; 12],
    pub regs_before: [u64; 12],
    pub insn: solana_sbpf::ebpf::Insn,

    pub mem: Option<MemoryAccess>,
    pub syscall: Option<SysCall>,

    pub cu_meter_before: CuMeter,
    // after execution
    pub cu_meter: CuMeter
}

#[derive(Debug, Default)]
pub struct InstructionConf {
    pub move_memory_instruction_classes: bool,
    pub loader_v1: bool,
}

#[derive(Debug)]
pub struct InstructionTrace {
    pub entries: Vec<Vec<TraceEntry>>,
    pub address_space: Vec<AddressSpace>,
    pub result: InstructionResult,
    pub conf: Vec<InstructionConf>,

    feature_set: FeatureSet,
    compute_budget: ComputeBudget,

    registered_syscalls: BTreeMap<u32, String>,

    pub cu_meter_final_value: Vec<CuMeter>,
    pub cu_initial_value: Vec<CuMeter>,

    pub cpi_calls: Vec<CPIEntry>,

    cpi_caller: Vec<usize>,
    cur_frame: usize,
    tx_context_keys: Vec<Pubkey>,

    pub return_data: BTreeMap<Pubkey, Vec<u8>>,
    pub instructions: Vec<Instruction>
}

#[derive(Clone)]
pub struct InstructionTraceBuilder {
    trace: Rc<RefCell<Option<InstructionTrace>>>,
    err: Rc<RefCell<Option<EmulationError>>>
}

impl TraceEntry {
    fn fill_memory_access(&mut self, address_space: &AddressSpace, move_memory_instruction_classes: bool) -> Result<(), EmulationError> {
        let src = self.insn.src as usize;
        let dst = self.insn.dst as usize;

        let mut mem: Option<MemoryAccess> = None;

        macro_rules! fill_mem_read {
            ($vmaddr:ident, $typ:ty, $value:expr) => {
                {
                    let len = std::mem::size_of::<$typ>();
                    let value = $value as $typ as u64;
                    let vmaddr = $vmaddr;
                    mem = Some(MemoryAccess::Read{size: len as u8, value, vmaddr:vmaddr});
                    let found = address_space.load::<$typ>(vmaddr)?;
                    if found != value {
                        return Err(EmulationError::MemoryConsistencyCheck{vmaddr, expected: value as u64, found});
                    }
                }
            }
        }
        macro_rules! fill_mem_write {
            ($vmaddr:ident, $typ:ty, $value:expr) => {
                {
                    let len = std::mem::size_of::<$typ>() as u8;
                    let vmaddr = $vmaddr;
                    let value = $value as $typ as u64;
                    let before = address_space.load::<$typ>(vmaddr)?;
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

        Ok(())
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
            syscall: None,
            cu_meter: 0.into(),
            cu_meter_before: 0.into()
        }
    }
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

    pub fn build(mollusk: &mut Mollusk, instruction: &Instruction, accounts: &[(Pubkey, Account)]) -> Result<InstructionTrace, EmulationError> {
        let this = Self {
            trace: RefCell::new(Some(InstructionTrace::default())).into(),
            err: RefCell::new(None).into(),
        };
        this.trace.borrow_mut().as_mut().unwrap().configure(mollusk);

        let mut cb: Box<dyn InvocationInspectCallback> = Box::new(this.clone());
        mem::swap(&mut cb, &mut mollusk.invocation_inspect_callback);
        let result = mollusk.process_instruction(instruction, accounts);
        TRACE_IN_PROGRESS.with(|addr| addr.replace(std::ptr::null_mut()));

        if let Some(err) = RefCell::borrow_mut(&this.err).take() {
            return Err(err)
        }

        this.trace.borrow_mut().as_mut().unwrap().result.absorb(result);

        let result = this.trace.borrow_mut().take().unwrap();
        Ok(result)
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
        match self.trace.borrow_mut().as_mut().unwrap().prepare(program_id, instruction_data, instruction_accounts, invoke_context) {
            Err(err) => {
                TRACE_IN_PROGRESS.with(|addr| addr.replace(std::ptr::null_mut()));
                self.err.replace(Some(EmulationError::InstructionError(err)));
            },
            _ => {}
        };
    }

    fn after_invocation(&self, invoke_context: &InvokeContext) {
        if RefCell::borrow(&self.err).borrow().is_none() {
           match self.trace.borrow_mut().as_mut().unwrap().finalize_frame(invoke_context) {
               Err(err) => { self.err.replace(Some(err)); },
               _ => {}
           }
        }
    }
}

thread_local! {
    static TRACE_IN_PROGRESS: RefCell<*mut InstructionTrace> = RefCell::new(std::ptr::null_mut());
}

macro_rules! invoke_syscall_stub {
    ($name:ident, $syscall:ident, $translate_instruction:path, $translate_signers:path, $translate_regions:path, $make_account_patch:path, $kind:expr) => {
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
                if TRACE_IN_PROGRESS.with_borrow(|trace| *trace.borrow()).is_null() {
                    return $syscall::rust(
                        invoke_context,
                        instruction_addr,
                        account_infos_addr,
                        account_infos_len,
                        signers_seeds_addr,
                        signers_seeds_len,
                        memory_mapping);
                }

                let check_aligned = invoke_context.get_check_aligned();

                macro_rules! check_call {
                    ($e:expr) => {
                        {
                            let result = $e;

                            if result.is_err() {
                                TRACE_IN_PROGRESS.with_borrow_mut(|trace| {
                                        let trace: &mut InstructionTrace = unsafe{&mut (**trace)};
                                        let meter = solana_sbpf::vm::ContextObject::get_remaining(invoke_context);
                                        trace.cpi_calls.push(
                                            CPIEntry {
                                                kind: $kind,
                                                program: Pubkey::from([0 as u8; 32]),
                                                instruction_data: vec![],
                                                instruction_accounts: vec![],
                                                caller_frame: trace.cur_frame,
                                                callee_frame: 0,
                                                cu_meter_before: meter.into(),
                                                cu_meter_after: meter.into(),
                                                return_data: vec![],
                                                acc_patches: vec![],
                                            });
                                    });
                            }

                            result?
                        }
                    }
                }

                let instruction = check_call!($translate_instruction(instruction_addr, memory_mapping, check_aligned));
                let regions = check_call!($translate_regions(account_infos_addr, account_infos_len, memory_mapping, invoke_context));

                let transaction_context = &invoke_context.transaction_context;
                let instruction_context = check_call!(transaction_context.get_current_instruction_context());
                let caller_program_id = check_call!(instruction_context.get_last_program_key(transaction_context));

                let signers = check_call!(
                    $translate_signers(
                        caller_program_id,
                        signers_seeds_addr,
                        signers_seeds_len,
                        memory_mapping,
                        check_aligned,
                    ));

                let (instruction_accounts, _) = check_call!(invoke_context.prepare_instruction(&instruction, &signers));

                let mut cpi_number: usize = 0;
                let frame_number = TRACE_IN_PROGRESS.with_borrow_mut(|trace| {
                    let trace: &mut InstructionTrace = unsafe{&mut (**trace)};
                    cpi_number = trace.cpi_calls.len();
                    let meter = solana_sbpf::vm::ContextObject::get_remaining(invoke_context);
                    trace.cpi_calls.push(
                        CPIEntry {
                            kind: $kind,
                            program: instruction.program_id,
                            instruction_data: instruction.data.to_vec(),
                            instruction_accounts: instruction_accounts.clone(),
                            caller_frame: trace.cur_frame,
                            callee_frame: 0,
                            cu_meter_before: meter.into(),
                            cu_meter_after: meter.into(),
                            return_data: vec![],
                            acc_patches: vec![],
                        });

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
                    {
                        let cpi_entry = &mut trace.cpi_calls[cpi_number];
                        for account in instruction.accounts.as_ref() {
                            if account.is_writable {
                                debug!("adding patch for {}", account.pubkey);
                                cpi_entry.acc_patches.push((account.pubkey,
                                        $make_account_patch(
                                            account.pubkey,
                                            account_infos_addr,
                                            account_infos_len,
                                            regions.as_slice(),
                                            memory_mapping,
                                            invoke_context)?));
                            }
                        }

                        let meter = solana_sbpf::vm::ContextObject::get_remaining(invoke_context);
                        cpi_entry.cu_meter_after = meter.into();
                        cpi_entry.callee_frame = frame_number;
                    }

                    trace.finalize_frame(invoke_context)
                })?;

                result
            }
        );
        
    };
}

invoke_syscall_stub!(
    SyscallInvokeSignedCStub,
    SyscallInvokeSignedC,
    syscall_decode::translate_instruction_c,
    syscall_decode::translate_signers_c,
    syscall_decode::translate_regions_c,
    syscall_decode::make_account_patch_c,
    CPIKind::C);

invoke_syscall_stub!(
    SyscallInvokeSignedRustStub,
    SyscallInvokeSignedRust,
    syscall_decode::translate_instruction_rust,
    syscall_decode::translate_signers_rust,
    syscall_decode::translate_regions_rust,
    syscall_decode::make_account_patch_rust,
    CPIKind::Rust);

impl Default for InstructionTrace {
    fn default() -> Self {
        Self {
            entries: vec![],
            result: InstructionResult::default(),
            address_space: vec![],
            conf: vec![],
            feature_set: FeatureSet::default(),
            compute_budget: ComputeBudget::default(),
            registered_syscalls: BTreeMap::new(),
            cu_initial_value: vec![],
            cu_meter_final_value: vec![],
            cpi_calls: vec![],
            cur_frame: 0,
            cpi_caller: vec![],
            tx_context_keys: vec![],
            instructions: vec![],
            return_data: BTreeMap::new()
        }
    }
}

pub fn debug_display_region(display: &str, r: &MemoryRegion) {
    println!("{display} memory region {} {} / {}", r.vm_addr, r.vm_addr_end, r.vm_gap_shift);
}


impl CuMeter {
    fn consume_cu(&mut self, value: u64) {
        self.0 = self.0.saturating_sub(value);
    }

    pub fn diff(&self, cu_meter: &CuMeter) -> u64 {
        self.0.saturating_sub(cu_meter.0)
    }
}    

impl From<u64> for CuMeter {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Into<u64> for CuMeter {
    fn into(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for CuMeter {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "cu meter ({})", self.0)
    }
}

pub fn replay_syscall(cost: &SVMTransactionExecutionCost, cu_meter: &mut CuMeter, address_space: &mut AddressSpace, op: &SysCall) -> Result<(), EmulationError> {
    macro_rules! consume_mem_op {
        ($n: expr) => {

            cu_meter.consume_cu(cost.mem_op_base_cost.max(
                $n.checked_div(cost.cpi_bytes_per_unit)
                    .unwrap_or(u64::MAX)));
        }
    }

    debug!("replaying {op:?}");
    match op {
        SysCall::MemCpy { dst, src, n} => {
            for i in 0..*n {
                address_space.store::<u8>(dst + i, address_space.load::<u8>(src + i)? as u8)?;
            }
            consume_mem_op!(n);
        },
        SysCall::MemCmp { s1, s2, n, result } => {
            let mut cmpresult: i32 = 0;
            for i in 0..*n as usize {
                let i = i as u64;
                let a = address_space.load::<u8>(*s1 + i)?;
                let b = address_space.load::<u8>(*s2 + i)?;
                if a != b {
                    cmpresult = (a as i32).saturating_sub(b as i32);
                    break;
                };
            }
            address_space.store(*result, cmpresult)?;
            consume_mem_op!(n);
        }
        SysCall::CPI(cpi_entry) => {
            for (_, patch) in cpi_entry.acc_patches.as_slice() {
                address_space.apply_patch(patch.lamports_patch.clone())?;
                address_space.apply_patch(patch.owner_patch.clone())?;
                if let Some(ref patch) = patch.data_len_patch {
                    address_space.apply_patch(patch.clone())?;
                }
                if let Some(ref patch) = patch.data_ptr_patch {
                    address_space.apply_patch(patch.clone())?;
                }
                if let Some(ref patch) = patch.data_slice_patch {
                    address_space.apply_patch(patch.clone())?;
                }
                address_space.override_region(&patch.mem_region_patch);
            }
            *cu_meter = cpi_entry.cu_meter_after.clone();
        },
        SysCall::Unknown(name) => {
            error!("unhandled syscall {name}");
        }
    }

    Ok(())
}

impl InstructionTrace {
    fn configure(&mut self, mollusk: &Mollusk) {
        for (key, (name, _)) in mollusk
            .program_cache
            .program_runtime_environment
            .get_function_registry()
            .iter()
        {
            self
                .registered_syscalls
                .insert(key, String::from_utf8(name.to_vec()).unwrap());
        }

        self.feature_set = mollusk.feature_set.clone();
        self.compute_budget = mollusk.compute_budget.clone();

        TRACE_IN_PROGRESS.with(|addr| addr.replace(self as *mut Self));
    }

    fn push_frame(&mut self, cu_meter: u64) {
        let caller = self.cur_frame;
        let calee = self.address_space.len();

        self.entries.push(vec![]);
        self.address_space.push(AddressSpace::default());

        self.cpi_caller.push(caller);
        self.cur_frame = calee;

        self.cu_initial_value.push(cu_meter.into());
        self.cu_meter_final_value.push(cu_meter.into());
    }

    fn pop_frame(&mut self) {
        self.cur_frame = self.cpi_caller.pop().unwrap();
    }
 
    fn prepare(&mut self,
        program_id: &Pubkey,
        instruction_data: &[u8],
        instruction_accounts: &[InstructionAccount],
        invoke_context: &InvokeContext) -> Result<usize, InstructionError>
    {
        let program_indices = vec![invoke_context.transaction_context.find_index_of_account(program_id).unwrap()];

        let cache = &invoke_context.program_cache_for_tx_batch;
        let ctx = &invoke_context.transaction_context;

        let cache_entry = cache.find(&program_id).or_panic_with(MolluskError::ProgramNotCached(&program_id));
        let cache_entry_type = &cache_entry.program;
        let loader_v1 = cache_entry.account_owner == ProgramCacheEntryOwner::LoaderV1;
        match cache_entry.account_owner {
            ProgramCacheEntryOwner::LoaderV1
                | ProgramCacheEntryOwner::LoaderV2
                | ProgramCacheEntryOwner::LoaderV3
                | ProgramCacheEntryOwner::LoaderV4 => {}
            _ => return Err(InstructionError::UnsupportedProgramId)
        }

        if self.tx_context_keys.is_empty() {
            let tx_context = &invoke_context.transaction_context;
            for i in 0..tx_context.get_number_of_accounts() {
                self.tx_context_keys.push(*tx_context.get_key_of_account_at_index(i as u16)?);
            }
        }

        let runtime_features = self.feature_set.runtime_features();
        let heap_size = self.compute_budget.heap_size as usize;
        self.push_frame(solana_sbpf::vm::ContextObject::get_remaining(invoke_context));
        self.cu_initial_value[self.cur_frame].consume_cu(calculate_heap_cost(heap_size as u32, self.compute_budget.to_cost().heap_cost));

        let address_space = self.address_space.last_mut().unwrap();
        self.instructions.push(Instruction {
            program_id: *program_id,
            data: instruction_data.to_vec(),
            accounts: instruction_accounts
                .iter()
                .map(|acc|
                    AccountMeta {
                        pubkey: self.tx_context_keys[acc.index_in_transaction as usize],
                        is_writable: acc.is_writable,
                        is_signer: acc.is_signer
                    }).collect()
            });

        match cache_entry_type  {
            solana_program_runtime::loaded_programs::ProgramCacheEntryType::Loaded(executable) => {

                let (vmaddr, text) = executable.get_text_bytes();
                address_space.text_vmaddr = vmaddr;
                address_space.text = text.to_vec();

                let ro_mem_region = executable.get_ro_region();
                assert!(ro_mem_region.vm_gap_shift == 63, "unexpected gap mode in elf ro region");
                let ro_mem = AlignedMemory::<{solana_sbpf::ebpf::HOST_ALIGN}>::from_slice(executable.get_ro_section());

                // as we copied ro memory it should start from the same vmaddr
                ro_mem_region.host_addr.set(ro_mem.as_slice().as_ptr() as u64);
                address_space.mem.push(ro_mem);
                address_space.regions.push(ro_mem_region);

                let stack_size = executable.get_config().stack_size() as usize;

                // heap memory
                let mut heap_memory = AlignedMemory::<{solana_sbpf::ebpf::HOST_ALIGN}>::zero_filled(heap_size);
                address_space.regions.push(MemoryRegion::new_writable(heap_memory.as_slice_mut(), solana_sbpf::ebpf::MM_HEAP_START));
                address_space.mem.push(heap_memory);

                // stack memory
                let mut stack_memory = AlignedMemory::<{solana_sbpf::ebpf::HOST_ALIGN}>::zero_filled(stack_size);
                address_space.regions.push(
                    MemoryRegion::new_writable_gapped(
                        stack_memory.as_slice_mut(),
                        solana_sbpf::ebpf::MM_STACK_START,
                        if !executable.get_sbpf_version().dynamic_stack_frames() && executable.get_config().enable_stack_frame_gaps {
                            executable.get_config().stack_frame_size as u64
                        } else {
                            0
                        },
                    )
                );
                address_space.mem.push(stack_memory);

                self.conf.push(InstructionConf{
                    move_memory_instruction_classes: executable.get_sbpf_version().move_memory_instruction_classes(),
                    loader_v1
                });
            },
            _ => panic!("{}", MolluskError::ProgramNotCached(&program_id))
        };

        let mut ictx = InstructionContext::default();
        ictx.configure(program_indices.as_slice(), instruction_accounts, &instruction_data);

        let mask_out_rent_epoch_in_vm_serialization = runtime_features.mask_out_rent_epoch_in_vm_serialization;

        let (serialized, regions, accounts_metadata) = serialize_parameters(ctx, &ictx, true, mask_out_rent_epoch_in_vm_serialization)?;
        
        address_space.mem.push(serialized);
        address_space.regions.extend(regions.into_iter());
        address_space.accounts = accounts_metadata;

        Ok(self.cur_frame)
    }

    fn finalize_frame(&mut self, ctx: &InvokeContext) -> Result<(), EmulationError> {
        let frame_number = self.cur_frame;
        let mut cu_meter = self.cu_initial_value[frame_number].clone();
        self.pop_frame();

        let trace = ctx.get_traces().last().unwrap();
        self.entries[frame_number] = trace.iter().map(
            |regs| TraceEntry::new(regs, &self.address_space[frame_number]))
                .collect::<Vec<TraceEntry>>();
        let mut address_space = self.address_space[frame_number].clone();
        let mut cpi_entries = self.cpi_calls.clone().into_iter().filter(|x| x.caller_frame == frame_number);

        let cost = self.compute_budget.to_cost();
        for i in 0..self.entries[frame_number].len() {
            let cu_before = cu_meter.clone();
            cu_meter.consume_cu(1);
            {
                let slice = &mut self.entries[frame_number][i..];
                let (fs, sc) = slice.split_at_mut(1);
                if !sc.is_empty() && !fs.is_empty() {
                    fs[0].regs_after = sc[0].regs_before;
                }
            }

            let cur = &mut self.entries[frame_number][i];
            cur.cu_meter_before = cu_before;
            cur.cu_meter = cu_meter.clone();
            cur.fill_memory_access(&address_space, self.conf[frame_number].move_memory_instruction_classes)?;

            {
                let mut selected_call: Option<&str> = None;
                let args = &cur.regs_before[1..6];
                if cur.insn.opc == solana_sbpf::ebpf::SYSCALL {
                    selected_call = self.registered_syscalls.get(&(cur.insn.imm as u32)).map(|r| r.as_str());
                }
                if cur.insn.opc == solana_sbpf::ebpf::CALL_IMM {
                    selected_call = self.registered_syscalls.get(&(cur.insn.imm as u32)).map(|r| r.as_str());
                }
                if let Some(selected_call) = selected_call { 
                    cur.syscall = match selected_call {
                        "sol_memcpy_" => Some(SysCall::MemCpy { src: args[1], dst: args[0], n: args[2] }),
                        "sol_memcmp_" => Some(SysCall::MemCmp { s1: args[0], s2: args[1], n: args[2], result: args[3] }),
                        "sol_invoke_signed_rust" | "sol_invoke_signed_c" => Some(SysCall::CPI (cpi_entries.next().expect("unmatched cpi entry").clone())),
                        _ => Some(SysCall::Unknown(selected_call.into()))
                    };
                }
            }

            let cur = cur.clone();
            if let Some(op@MemoryAccess::Write {..}) = &cur.mem {
                address_space.replay(op.clone())?;
            }
            if let Some(ref syscall) = &cur.syscall {
                replay_syscall(&cost, &mut cu_meter, &mut address_space, syscall)?;
            }
        }
        assert!(cpi_entries.next().is_none());

        self.cu_meter_final_value[frame_number] = cu_meter;

        Ok(())
    }
}
