use {
    mollusk_svm::{program::{create_program_account_loader_v3, ProgramCache}, Mollusk}, solana_program_runtime::{
        invoke_context::InvokeContext,
        solana_sbpf::{declare_builtin_function, memory_region::MemoryMapping},
    }, solana_sdk::{
        account::Account, bpf_loader_upgradeable, instruction::{AccountMeta, Instruction}, pubkey::Pubkey
    }, std::str::FromStr, svm_tracer::{debug_display_region, InstructionTrace, InstructionTraceBuilder}
};


declare_builtin_function!(
    /// A custom syscall to burn CUs.
    SyscallBurnCus,
    fn rust(
        invoke_context: &mut InvokeContext,
        to_burn: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        invoke_context.consume_checked(to_burn)?;
        Ok(0)
    }
);

fn instruction_burn_cus(program_id: &Pubkey, to_burn: u64) -> Instruction {
    Instruction::new_with_bytes(*program_id, &to_burn.to_le_bytes(), vec![])
}

declare_builtin_function!(
    /// A custom syscall to burn CUs.
    SyscallInspect,
    fn rust(
        invoke_context: &mut InvokeContext,
        to_burn: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        for r in memory_mapping.get_regions() {
            debug_display_region("inspect region", r);
        }
        Ok(0)
    }
);

fn main() {
    let program_id = Pubkey::new_unique();
    let key1 = Pubkey::new_unique();
    let key2 = Pubkey::new_unique();

    let cpi_target_program_id = Pubkey::new_unique();
    let instruction = Instruction::new_with_bytes(
        program_id,
        &u64::to_le_bytes(600),
        vec![
            AccountMeta::new(key1, false),
            AccountMeta::new_readonly(key2, false),
            AccountMeta::new_readonly(cpi_target_program_id, false),
        ],
    );

    let accounts = vec![
        (key1, Account::default()),
        (key2, Account::default()),
        (cpi_target_program_id, create_program_account_loader_v3(&cpi_target_program_id)),
    ];

    let mut mollusk = Mollusk::default();
    mollusk
        .program_cache.program_runtime_environment
        //.register_function("sol_burn_cus", SyscallBurnCus::vm)
        .register_function("sol_inspect", SyscallInspect::vm)
        .unwrap();

    let _ = InstructionTraceBuilder::prepare_for_tracing(&mut mollusk);

    println!("fun registered");

    let env = &mollusk.program_cache.program_runtime_environment;
    let config = env.get_config();
    println!("env.config is {config:?}");

    mollusk.add_program(&program_id, "sample", &bpf_loader_upgradeable::id());
    mollusk.add_program(&cpi_target_program_id, "cpi-target", &bpf_loader_upgradeable::id());

    // Execute the instruction and get the result.
    let trace = InstructionTraceBuilder::build(&mut mollusk, &instruction, &accounts).expect("trace build error");

    println!("cu meters {} {} difference {}",  trace.cu_initial_value[0], trace.cu_meter_final_value[0], trace.cu_initial_value[0].diff(&trace.cu_meter_final_value[0]));
    let result = trace.result;
    println!("Hello, mollusk! \n{result:?}");

    for trace in trace.entries {
        println!("frame");
        for entry in trace {
            let mem = entry.mem;
            //println!("{mem:?}")
        }
    }
}
