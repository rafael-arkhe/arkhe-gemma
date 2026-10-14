#![no_main]
use arkhe_p0_foundation::decode_canonical;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode_canonical(data);
});
