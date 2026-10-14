use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CanonicalValue>),
    Map(Vec<(CanonicalValue, CanonicalValue)>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_input_bytes: usize,
    pub max_bstr_bytes: usize,
    pub max_tstr_utf8_bytes: usize,
    pub max_collection_members: usize,
    pub max_nesting_depth: usize,
    /// Cumulative item budget for the entire decode tree.
    /// Conservative decoder item-cost budget. This is not an exact decoded-node count.
    pub max_item_cost: u64,
    /// Cumulative allocation budget charged before allocation.
    /// Conservative allocation-cost budget charged before allocations/copies.
    pub max_allocation_cost_bytes: u64,
    /// Maximum eager Vec preallocation even if a collection is within semantic limits.
    pub max_prealloc_members: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
            max_bstr_bytes: 512 * 1024,
            max_tstr_utf8_bytes: 512 * 1024,
            max_collection_members: 4096,
            max_nesting_depth: 64,
            max_item_cost: 16_384,
            max_allocation_cost_bytes: 2 * 1024 * 1024,
            max_prealloc_members: 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Conservative cost accounting. Charging may intentionally exceed exact heap usage;
/// security depends on rejecting before allocation when declared cost exceeds budget.
struct DecoderState {
    remaining_item_cost: u64,
    remaining_allocation_cost_bytes: u64,
}

impl DecoderState {
    fn new(limits: DecodeLimits) -> Self {
        Self {
            remaining_item_cost: limits.max_item_cost,
            remaining_allocation_cost_bytes: limits.max_allocation_cost_bytes,
        }
    }

    fn charge_item_cost(&mut self, cost: u64) -> Result<(), CanonicalError> {
        if cost > self.remaining_item_cost {
            return Err(CanonicalError::ItemBudgetExceeded {
                requested: cost,
                remaining: self.remaining_item_cost,
            });
        }
        self.remaining_item_cost -= cost;
        Ok(())
    }

    fn charge_allocation_cost(&mut self, bytes: u64) -> Result<(), CanonicalError> {
        if bytes > self.remaining_allocation_cost_bytes {
            return Err(CanonicalError::AllocationBudgetExceeded {
                requested: bytes,
                remaining: self.remaining_allocation_cost_bytes,
            });
        }
        self.remaining_allocation_cost_bytes -= bytes;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalError {
    InvalidNegativeInteger(i64),
    DuplicateMapKey,
    LengthOverflow,
    UnexpectedEof,
    TrailingBytes,
    UnsupportedMajorType(u8),
    UnsupportedSimpleValue(u8),
    FloatForbidden,
    TagForbidden,
    IndefiniteLengthForbidden,
    NonShortestInteger,
    InvalidUtf8,
    NonCanonicalMapOrder,
    InputTooLarge { declared: usize, max: usize },
    ByteStringTooLarge { declared: usize, max: usize },
    TextStringTooLarge { declared: usize, max: usize },
    CollectionTooLarge { declared: usize, max: usize },
    NestingTooDeep { depth: usize, max: usize },
    ItemBudgetExceeded { requested: u64, remaining: u64 },
    AllocationBudgetExceeded { requested: u64, remaining: u64 },
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CanonicalError::*;
        match self {
            InvalidNegativeInteger(v) => write!(f, "negative integer variant requires value < 0, got {v}"),
            DuplicateMapKey => write!(f, "duplicate canonical map key"),
            LengthOverflow => write!(f, "value length does not fit canonical CBOR length"),
            UnexpectedEof => write!(f, "unexpected end of input"),
            TrailingBytes => write!(f, "trailing bytes after canonical object"),
            UnsupportedMajorType(v) => write!(f, "unsupported CBOR major type {v}"),
            UnsupportedSimpleValue(v) => write!(f, "unsupported CBOR simple value {v:#x}"),
            FloatForbidden => write!(f, "floating point values are forbidden by the Arkhe profile"),
            TagForbidden => write!(f, "CBOR tags are forbidden by the Arkhe profile"),
            IndefiniteLengthForbidden => write!(f, "indefinite-length CBOR is forbidden"),
            NonShortestInteger => write!(f, "integer/length is not encoded in shortest form"),
            InvalidUtf8 => write!(f, "text string is not valid UTF-8"),
            NonCanonicalMapOrder => write!(f, "map keys are not in deterministic canonical order"),
            InputTooLarge { declared, max } => write!(f, "input size {declared} exceeds max {max}"),
            ByteStringTooLarge { declared, max } => write!(f, "byte string length {declared} exceeds max {max}"),
            TextStringTooLarge { declared, max } => write!(f, "text string length {declared} exceeds max {max}"),
            CollectionTooLarge { declared, max } => write!(f, "collection length {declared} exceeds max {max}"),
            NestingTooDeep { depth, max } => write!(f, "nesting depth {depth} exceeds max {max}"),
            ItemBudgetExceeded { requested, remaining } =>
                write!(f, "item budget exceeded: requested {requested}, remaining {remaining}"),
            AllocationBudgetExceeded { requested, remaining } =>
                write!(f, "allocation budget exceeded: requested {requested}, remaining {remaining}"),
        }
    }
}

impl std::error::Error for CanonicalError {}

pub fn canonical_bytes(value: &CanonicalValue) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    encode_value(value, &mut out)?;
    Ok(out)
}

pub fn decode_canonical(input: &[u8]) -> Result<CanonicalValue, CanonicalError> {
    decode_canonical_with_limits(input, DecodeLimits::default())
}

pub fn decode_canonical_with_limits(
    input: &[u8],
    limits: DecodeLimits,
) -> Result<CanonicalValue, CanonicalError> {
    if input.len() > limits.max_input_bytes {
        return Err(CanonicalError::InputTooLarge {
            declared: input.len(),
            max: limits.max_input_bytes,
        });
    }
    let mut pos = 0usize;
    let mut state = DecoderState::new(limits);
    let value = decode_value(input, &mut pos, 0, limits, &mut state)?;
    if pos != input.len() {
        return Err(CanonicalError::TrailingBytes);
    }
    Ok(value)
}

fn encode_value(value: &CanonicalValue, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        CanonicalValue::Null => out.push(0xf6),
        CanonicalValue::Bool(false) => out.push(0xf4),
        CanonicalValue::Bool(true) => out.push(0xf5),
        CanonicalValue::Unsigned(v) => encode_head(0, *v, out),
        CanonicalValue::Negative(v) => {
            if *v >= 0 {
                return Err(CanonicalError::InvalidNegativeInteger(*v));
            }
            let n = (-1i128 - i128::from(*v)) as u64;
            encode_head(1, n, out);
        }
        CanonicalValue::Bytes(bytes) => {
            encode_head(2, u64::try_from(bytes.len()).map_err(|_| CanonicalError::LengthOverflow)?, out);
            out.extend_from_slice(bytes);
        }
        CanonicalValue::Text(text) => {
            let bytes = text.as_bytes();
            encode_head(3, u64::try_from(bytes.len()).map_err(|_| CanonicalError::LengthOverflow)?, out);
            out.extend_from_slice(bytes);
        }
        CanonicalValue::Array(items) => {
            encode_head(4, u64::try_from(items.len()).map_err(|_| CanonicalError::LengthOverflow)?, out);
            for item in items {
                encode_value(item, out)?;
            }
        }
        CanonicalValue::Map(entries) => {
            let mut encoded = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                encoded.push((canonical_bytes(key)?, canonical_bytes(value)?));
            }
            encoded.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
            for pair in encoded.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(CanonicalError::DuplicateMapKey);
                }
            }
            encode_head(5, u64::try_from(encoded.len()).map_err(|_| CanonicalError::LengthOverflow)?, out);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                out.extend_from_slice(&value);
            }
        }
    }
    Ok(())
}

fn decode_value(
    input: &[u8],
    pos: &mut usize,
    depth: usize,
    limits: DecodeLimits,
    state: &mut DecoderState,
) -> Result<CanonicalValue, CanonicalError> {
    if depth > limits.max_nesting_depth {
        return Err(CanonicalError::NestingTooDeep { depth, max: limits.max_nesting_depth });
    }

    state.charge_item_cost(1)?;

    let initial = *input.get(*pos).ok_or(CanonicalError::UnexpectedEof)?;
    *pos += 1;
    let major = initial >> 5;
    let ai = initial & 0x1f;

    match major {
        0 => Ok(CanonicalValue::Unsigned(read_arg(input, pos, ai)?)),
        1 => {
            let n = read_arg(input, pos, ai)?;
            if n > i64::MAX as u64 {
                return Err(CanonicalError::LengthOverflow);
            }
            Ok(CanonicalValue::Negative(-1 - (n as i64)))
        }
        2 => {
            let len = read_len(input, pos, ai)?;
            if len > limits.max_bstr_bytes {
                return Err(CanonicalError::ByteStringTooLarge { declared: len, max: limits.max_bstr_bytes });
            }
            state.charge_allocation_cost(u64::try_from(len).map_err(|_| CanonicalError::LengthOverflow)?)?;
            Ok(CanonicalValue::Bytes(take(input, pos, len)?.to_vec()))
        }
        3 => {
            let len = read_len(input, pos, ai)?;
            if len > limits.max_tstr_utf8_bytes {
                return Err(CanonicalError::TextStringTooLarge { declared: len, max: limits.max_tstr_utf8_bytes });
            }
            state.charge_allocation_cost(u64::try_from(len).map_err(|_| CanonicalError::LengthOverflow)?)?;
            let raw = take(input, pos, len)?;
            let text = std::str::from_utf8(raw).map_err(|_| CanonicalError::InvalidUtf8)?;
            Ok(CanonicalValue::Text(text.to_owned()))
        }
        4 => {
            let len = read_len(input, pos, ai)?;
            if len > limits.max_collection_members {
                return Err(CanonicalError::CollectionTooLarge { declared: len, max: limits.max_collection_members });
            }

            // Charge declared collection cost before allocation/iteration.
            state.charge_item_cost(u64::try_from(len).map_err(|_| CanonicalError::LengthOverflow)?)?;
            let prealloc = len.min(limits.max_prealloc_members);
            let approx = u64::try_from(prealloc)
                .map_err(|_| CanonicalError::LengthOverflow)?
                .saturating_mul(std::mem::size_of::<CanonicalValue>() as u64);
            state.charge_allocation_cost(approx)?;

            let mut items = Vec::with_capacity(prealloc);
            for _ in 0..len {
                items.push(decode_value(input, pos, depth + 1, limits, state)?);
            }
            Ok(CanonicalValue::Array(items))
        }
        5 => {
            let len = read_len(input, pos, ai)?;
            if len > limits.max_collection_members {
                return Err(CanonicalError::CollectionTooLarge { declared: len, max: limits.max_collection_members });
            }

            // Map has key+value items: charge both at declaration.
            let declared_items = u64::try_from(len)
                .map_err(|_| CanonicalError::LengthOverflow)?
                .saturating_mul(2);
            state.charge_item_cost(declared_items)?;

            let prealloc = len.min(limits.max_prealloc_members);
            let approx = u64::try_from(prealloc)
                .map_err(|_| CanonicalError::LengthOverflow)?
                .saturating_mul(std::mem::size_of::<(CanonicalValue, CanonicalValue)>() as u64);
            state.charge_allocation_cost(approx)?;

            let mut entries = Vec::with_capacity(prealloc);
            let mut previous_key_bytes: Option<Vec<u8>> = None;
            for _ in 0..len {
                let key_start = *pos;
                let key = decode_value(input, pos, depth + 1, limits, state)?;
                let key_len = pos.checked_sub(key_start).ok_or(CanonicalError::LengthOverflow)?;
                state.charge_allocation_cost(
                    u64::try_from(key_len).map_err(|_| CanonicalError::LengthOverflow)?
                )?;
                let key_bytes = input[key_start..*pos].to_vec();

                if let Some(prev) = &previous_key_bytes {
                    match canonical_key_cmp(prev, &key_bytes) {
                        Ordering::Less => {}
                        Ordering::Equal => return Err(CanonicalError::DuplicateMapKey),
                        Ordering::Greater => return Err(CanonicalError::NonCanonicalMapOrder),
                    }
                }
                previous_key_bytes = Some(key_bytes);
                let value = decode_value(input, pos, depth + 1, limits, state)?;
                entries.push((key, value));
            }
            Ok(CanonicalValue::Map(entries))
        }
        6 => Err(CanonicalError::TagForbidden),
        7 => match ai {
            20 => Ok(CanonicalValue::Bool(false)),
            21 => Ok(CanonicalValue::Bool(true)),
            22 => Ok(CanonicalValue::Null),
            25..=27 => Err(CanonicalError::FloatForbidden),
            31 => Err(CanonicalError::IndefiniteLengthForbidden),
            other => Err(CanonicalError::UnsupportedSimpleValue(other)),
        },
        other => Err(CanonicalError::UnsupportedMajorType(other)),
    }
}

fn read_len(input: &[u8], pos: &mut usize, ai: u8) -> Result<usize, CanonicalError> {
    if ai == 31 { return Err(CanonicalError::IndefiniteLengthForbidden); }
    usize::try_from(read_arg(input, pos, ai)?).map_err(|_| CanonicalError::LengthOverflow)
}

fn read_arg(input: &[u8], pos: &mut usize, ai: u8) -> Result<u64, CanonicalError> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            let v = take(input, pos, 1)?[0] as u64;
            if v < 24 { return Err(CanonicalError::NonShortestInteger); }
            Ok(v)
        }
        25 => {
            let b = take(input, pos, 2)?;
            let v = u16::from_be_bytes([b[0], b[1]]) as u64;
            if v <= 0xff { return Err(CanonicalError::NonShortestInteger); }
            Ok(v)
        }
        26 => {
            let b = take(input, pos, 4)?;
            let v = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            if v <= 0xffff { return Err(CanonicalError::NonShortestInteger); }
            Ok(v)
        }
        27 => {
            let b = take(input, pos, 8)?;
            let v = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            if v <= 0xffff_ffff { return Err(CanonicalError::NonShortestInteger); }
            Ok(v)
        }
        28..=30 => Err(CanonicalError::UnsupportedSimpleValue(ai)),
        31 => Err(CanonicalError::IndefiniteLengthForbidden),
        32_u8..=u8::MAX => Err(CanonicalError::UnsupportedSimpleValue(ai)),
    }
}

fn take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], CanonicalError> {
    let end = pos.checked_add(len).ok_or(CanonicalError::LengthOverflow)?;
    if end > input.len() { return Err(CanonicalError::UnexpectedEof); }
    let slice = &input[*pos..end];
    *pos = end;
    Ok(slice)
}

fn encode_head(major: u8, value: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => { out.push(prefix | 24); out.push(value as u8); }
        0x100..=0xffff => { out.push(prefix | 25); out.extend_from_slice(&(value as u16).to_be_bytes()); }
        0x1_0000..=0xffff_ffff => { out.push(prefix | 26); out.extend_from_slice(&(value as u32).to_be_bytes()); }
        _ => { out.push(prefix | 27); out.extend_from_slice(&value.to_be_bytes()); }
    }
}

fn canonical_key_cmp(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}
