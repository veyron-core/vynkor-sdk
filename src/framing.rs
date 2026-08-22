//! Re-exports of the kernel framing layer — the single source of truth for
//! the Veyron wire format (`docs/FRAMING.md`). The SDK never redefines flag
//! constants or frame parsing; it shares the kernel implementation so the two
//! sides cannot drift.

pub use vynkor_wire::framing::{
    parse_frag_header, read_frame, read_frame_with_timeout, serialize_header, target_as_str,
    write_frame, write_frame_raw, FragmentHeader, Frame, COMPRESS_THRESHOLD, FLAG_COMPRESSED,
    FLAG_FRAGMENTED, FLAG_MAC_PRESENT, FLAG_RAW_BINARY, FRAG_HEADER_SIZE, MAX_PAYLOAD_SIZE,
};
