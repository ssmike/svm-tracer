use solana_instruction::error::InstructionError;

#[derive(Debug)]
pub enum EmulationError {
    AddressTranslationError{vmaddr: u64},
    MemoryConsistencyCheck{vmaddr: u64, value: u64},
    InstructionError(InstructionError),
}

impl std::error::Error for EmulationError { }

impl std::fmt::Display for EmulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressTranslationError { vmaddr } => write!(f, "address translation {vmaddr} failed"),
            Self::MemoryConsistencyCheck { vmaddr, value } => write!(f, "memory load consistency check {vmaddr} with value {value}"),
            Self::InstructionError(err) => std::fmt::Display::fmt(&err, f)
        }
    }
}

