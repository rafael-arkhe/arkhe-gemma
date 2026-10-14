use arkhe_p0_foundation::{
    canonical_bytes, decode_canonical, CanonicalValue,
};

fn pseudo(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn gen_value(seed: &mut u64, depth: usize) -> CanonicalValue {
    if depth >= 4 {
        return CanonicalValue::Unsigned(pseudo(seed) % 1000);
    }
    match pseudo(seed) % 7 {
        0 => CanonicalValue::Null,
        1 => CanonicalValue::Bool((pseudo(seed) & 1) == 1),
        2 => CanonicalValue::Unsigned(pseudo(seed)),
        3 => CanonicalValue::Text(format!("v-{}", pseudo(seed) % 10_000)),
        4 => CanonicalValue::Bytes((pseudo(seed).to_be_bytes()[..4]).to_vec()),
        5 => {
            let n = (pseudo(seed) % 4) as usize;
            CanonicalValue::Array((0..n).map(|_| gen_value(seed, depth + 1)).collect())
        }
        _ => {
            let n = (pseudo(seed) % 4) as usize;
            let mut entries = Vec::new();
            for i in 0..n {
                entries.push((
                    CanonicalValue::Text(format!("k-{depth}-{i}")),
                    gen_value(seed, depth + 1),
                ));
            }
            CanonicalValue::Map(entries)
        }
    }
}

#[test]
fn deterministic_roundtrip_property_sample() {
    let mut seed = 0x41524b48455f5030u64;
    for _ in 0..2000 {
        let value = gen_value(&mut seed, 0);
        let bytes = canonical_bytes(&value).unwrap();
        let decoded = decode_canonical(&bytes).unwrap();
        let bytes2 = canonical_bytes(&decoded).unwrap();
        assert_eq!(bytes, bytes2);
    }
}

#[test]
fn arbitrary_short_inputs_never_panic_sample() {
    let mut seed = 0xdec0de1234567890u64;
    for len in 0..256usize {
        for _ in 0..16 {
            let mut input = vec![0u8; len];
            for b in &mut input {
                *b = pseudo(&mut seed) as u8;
            }
            let result = std::panic::catch_unwind(|| decode_canonical(&input));
            assert!(result.is_ok(), "decoder panicked for input length {len}");
        }
    }
}
