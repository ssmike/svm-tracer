use solana_instruction::error::InstructionError;

#[derive(Debug)]
pub enum EmulationError {
    AddressTranslationError{vmaddr: u64},
    MemoryConsistencyCheck{vmaddr: u64, expected: u64, found: u64},
    InstructionError(InstructionError),
    CustomError(Box<dyn std::error::Error>)
}

impl std::error::Error for EmulationError { }

impl std::fmt::Display for EmulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressTranslationError { vmaddr } => write!(f, "address translation {vmaddr} failed"),
            Self::MemoryConsistencyCheck { vmaddr, expected, found } => write!(f, "memory load consistency check {vmaddr} with value {found} instead of {expected}"),
            Self::InstructionError(err) => std::fmt::Display::fmt(&err, f),
            Self::CustomError(err) => err.fmt(f),
        }
    }
}

impl From<Box<dyn std::error::Error>> for EmulationError {
    fn from(value: Box<dyn std::error::Error>) -> Self {
        EmulationError::CustomError(value)
    }
}
