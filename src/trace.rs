use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Fixed 8-byte trace header magic: "CAUSAL\0\0"
pub const TRACE_HEADER_MAGIC: &[u8; 8] = b"CAUSAL\0\0";

/// Fixed 8-byte trace footer magic: "CAUSEND\0"
pub const TRACE_FOOTER_MAGIC: &[u8; 8] = b"CAUSEND\0";

/// Supported trace format version (V1).
pub const TRACE_VERSION_1: u32 = 1;

/// Architecture ID for Linux x86-64.
pub const ARCH_X86_64: u16 = 1;

/// Byte order ID for little-endian.
pub const BYTE_ORDER_LITTLE_ENDIAN: u8 = 1;

/// Pointer width in bytes for 64-bit architecture.
pub const POINTER_WIDTH_64: u8 = 8;

/// Event kind identifier for SyscallEnter.
pub const EVENT_KIND_SYSCALL_ENTER: u8 = 1;

/// Event kind identifier for SyscallExit.
pub const EVENT_KIND_SYSCALL_EXIT: u8 = 2;

/// Fixed record length for SyscallEnter (excluding 4-byte length prefix).
pub const RECORD_LEN_SYSCALL_ENTER: u32 = 72;

/// Fixed record length for SyscallExit (excluding 4-byte length prefix).
pub const RECORD_LEN_SYSCALL_EXIT: u32 = 32;

/// Total size of trace header in bytes.
pub const HEADER_SIZE: usize = 16;

/// Total size of trace footer in bytes.
pub const FOOTER_SIZE: usize = 16;

/// Known Linux x86-64 terminating syscall numbers.
pub const SYS_EXIT_X86_64: u64 = 60;
pub const SYS_EXIT_GROUP_X86_64: u64 = 231;

/// In-memory representation of a parsed trace event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceEvent {
    SyscallEnter {
        event_id: u64,
        tid: u32,
        number: u64,
        args: [u64; 6],
    },
    SyscallExit {
        event_id: u64,
        tid: u32,
        number: u64,
        result: i64,
    },
}

impl TraceEvent {
    pub fn event_id(&self) -> u64 {
        match self {
            TraceEvent::SyscallEnter { event_id, .. } => *event_id,
            TraceEvent::SyscallExit { event_id, .. } => *event_id,
        }
    }

    pub fn tid(&self) -> u32 {
        match self {
            TraceEvent::SyscallEnter { tid, .. } => *tid,
            TraceEvent::SyscallExit { tid, .. } => *tid,
        }
    }
}

/// Streaming trace writer that encodes V1 binary format directly to an `io::Write` sink.
pub struct TraceWriter<W: Write> {
    writer: W,
    next_event_id: u64,
    event_count: u64,
    finished: bool,
}

impl<W: Write> TraceWriter<W> {
    /// Creates a new `TraceWriter` and writes the 16-byte V1 header immediately.
    pub fn new(mut writer: W) -> Result<Self, io::Error> {
        let mut header = [0_u8; HEADER_SIZE];
        header[0..8].copy_from_slice(TRACE_HEADER_MAGIC);
        header[8..12].copy_from_slice(&TRACE_VERSION_1.to_le_bytes());
        header[12..14].copy_from_slice(&ARCH_X86_64.to_le_bytes());
        header[14] = BYTE_ORDER_LITTLE_ENDIAN;
        header[15] = POINTER_WIDTH_64;

        writer.write_all(&header)?;

        Ok(Self {
            writer,
            next_event_id: 1,
            event_count: 0,
            finished: false,
        })
    }

    /// Encodes and writes a `SyscallEnter` event record.
    pub fn write_syscall_enter(
        &mut self,
        tid: u32,
        number: u64,
        args: [u64; 6],
    ) -> Result<u64, io::Error> {
        if self.finished {
            return Err(io::Error::other(
                "cannot write event to finished trace writer",
            ));
        }

        let event_id = self.next_event_id;
        let mut buf = [0_u8; (4 + RECORD_LEN_SYSCALL_ENTER) as usize];

        // 4-byte record length prefix
        buf[0..4].copy_from_slice(&RECORD_LEN_SYSCALL_ENTER.to_le_bytes());
        // Event header (kind + 3 reserved bytes)
        buf[4] = EVENT_KIND_SYSCALL_ENTER;
        buf[5..8].copy_from_slice(&[0_u8; 3]);
        // Event metadata
        buf[8..16].copy_from_slice(&event_id.to_le_bytes());
        buf[16..20].copy_from_slice(&tid.to_le_bytes());
        // Payload: syscall number + 6 args
        buf[20..28].copy_from_slice(&number.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            let start = 28 + i * 8;
            buf[start..start + 8].copy_from_slice(&arg.to_le_bytes());
        }

        self.writer.write_all(&buf)?;
        self.next_event_id += 1;
        self.event_count += 1;
        Ok(event_id)
    }

    /// Encodes and writes a `SyscallExit` event record.
    pub fn write_syscall_exit(
        &mut self,
        tid: u32,
        number: u64,
        result: i64,
    ) -> Result<u64, io::Error> {
        if self.finished {
            return Err(io::Error::other(
                "cannot write event to finished trace writer",
            ));
        }

        let event_id = self.next_event_id;
        let mut buf = [0_u8; (4 + RECORD_LEN_SYSCALL_EXIT) as usize];

        // 4-byte record length prefix
        buf[0..4].copy_from_slice(&RECORD_LEN_SYSCALL_EXIT.to_le_bytes());
        // Event header (kind + 3 reserved bytes)
        buf[4] = EVENT_KIND_SYSCALL_EXIT;
        buf[5..8].copy_from_slice(&[0_u8; 3]);
        // Event metadata
        buf[8..16].copy_from_slice(&event_id.to_le_bytes());
        buf[16..20].copy_from_slice(&tid.to_le_bytes());
        // Payload: syscall number + result
        buf[20..28].copy_from_slice(&number.to_le_bytes());
        buf[28..36].copy_from_slice(&result.to_le_bytes());

        self.writer.write_all(&buf)?;
        self.next_event_id += 1;
        self.event_count += 1;
        Ok(event_id)
    }

    /// Writes the 16-byte completion footer and flushes the underlying writer.
    pub fn finish(&mut self) -> Result<(), io::Error> {
        if self.finished {
            return Ok(());
        }

        let mut footer = [0_u8; FOOTER_SIZE];
        footer[0..8].copy_from_slice(&self.event_count.to_le_bytes());
        footer[8..16].copy_from_slice(TRACE_FOOTER_MAGIC);

        self.writer.write_all(&footer)?;
        self.writer.flush()?;
        self.finished = true;
        Ok(())
    }
}

/// Parses raw trace bytes into validated `TraceEvent` objects.
pub fn parse_trace_bytes(bytes: &[u8]) -> Result<Vec<TraceEvent>, String> {
    if bytes.len() < HEADER_SIZE + FOOTER_SIZE {
        return Err(format!(
            "incomplete trace: size {} bytes is smaller than minimum header + footer size ({} bytes)",
            bytes.len(),
            HEADER_SIZE + FOOTER_SIZE
        ));
    }

    // 1. Validate Header
    let magic = &bytes[0..8];
    if magic != TRACE_HEADER_MAGIC {
        return Err(format!(
            "invalid trace header magic: expected {:?}, got {:?}",
            TRACE_HEADER_MAGIC, magic
        ));
    }

    let version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| "failed to read format version".to_string())?,
    );
    if version != TRACE_VERSION_1 {
        return Err(format!(
            "unsupported trace format version {}; supported version: 1",
            version
        ));
    }

    let arch = u16::from_le_bytes(
        bytes[12..14]
            .try_into()
            .map_err(|_| "failed to read architecture".to_string())?,
    );
    if arch != ARCH_X86_64 {
        return Err(format!("unsupported trace architecture id {}", arch));
    }

    let byte_order = bytes[14];
    if byte_order != BYTE_ORDER_LITTLE_ENDIAN {
        return Err(format!("unsupported byte order id {}", byte_order));
    }

    let pointer_width = bytes[15];
    if pointer_width != POINTER_WIDTH_64 {
        return Err(format!("unsupported pointer width {}", pointer_width));
    }

    // 2. Validate Footer location and content
    let footer_start = bytes.len() - FOOTER_SIZE;
    let expected_event_count = u64::from_le_bytes(
        bytes[footer_start..footer_start + 8]
            .try_into()
            .map_err(|_| "failed to read footer event count".to_string())?,
    );
    let footer_magic = &bytes[footer_start + 8..bytes.len()];
    if footer_magic != TRACE_FOOTER_MAGIC {
        return Err(format!(
            "incomplete trace: completion footer missing or invalid footer magic (got {:?})",
            footer_magic
        ));
    }

    // 3. Parse Framed Event Records
    let mut offset = HEADER_SIZE;
    let mut events = Vec::new();
    let mut expected_event_id: u64 = 1;

    while offset < footer_start {
        if offset + 4 > footer_start {
            return Err("truncated record length prefix".to_string());
        }

        let record_len = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| "failed to read record length".to_string())?,
        ) as usize;
        offset += 4;

        if offset.checked_add(record_len).is_none() || offset + record_len > footer_start {
            return Err(format!(
                "record length {} extends past event data region into footer",
                record_len
            ));
        }

        let record_body = &bytes[offset..offset + record_len];
        offset += record_len;

        if record_body.len() < 16 {
            return Err("record body is shorter than minimum event header".to_string());
        }

        let kind = record_body[0];
        let reserved = &record_body[1..4];
        if reserved != [0_u8; 3] {
            return Err(format!(
                "nonzero reserved bytes in event {}: {:?}",
                expected_event_id, reserved
            ));
        }

        let event_id = u64::from_le_bytes(
            record_body[4..12]
                .try_into()
                .map_err(|_| "failed to read event id".to_string())?,
        );
        if event_id != expected_event_id {
            return Err(format!(
                "non-monotonic event id: observed {}, expected {}",
                event_id, expected_event_id
            ));
        }

        let tid = u32::from_le_bytes(
            record_body[12..16]
                .try_into()
                .map_err(|_| "failed to read tid".to_string())?,
        );
        if tid == 0 {
            return Err(format!("invalid tid 0 in event {}", event_id));
        }

        match kind {
            EVENT_KIND_SYSCALL_ENTER => {
                if record_len != RECORD_LEN_SYSCALL_ENTER as usize {
                    return Err(format!(
                        "trace event {}: SyscallEnter record length {}, expected {}",
                        event_id, record_len, RECORD_LEN_SYSCALL_ENTER
                    ));
                }
                let number = u64::from_le_bytes(
                    record_body[16..24]
                        .try_into()
                        .map_err(|_| "failed to read syscall number".to_string())?,
                );
                let mut args = [0_u64; 6];
                for (i, arg_slot) in args.iter_mut().enumerate() {
                    let arg_start = 24 + i * 8;
                    *arg_slot = u64::from_le_bytes(
                        record_body[arg_start..arg_start + 8]
                            .try_into()
                            .map_err(|_| "failed to read syscall arg".to_string())?,
                    );
                }
                events.push(TraceEvent::SyscallEnter {
                    event_id,
                    tid,
                    number,
                    args,
                });
            }
            EVENT_KIND_SYSCALL_EXIT => {
                if record_len != RECORD_LEN_SYSCALL_EXIT as usize {
                    return Err(format!(
                        "trace event {}: SyscallExit record length {}, expected {}",
                        event_id, record_len, RECORD_LEN_SYSCALL_EXIT
                    ));
                }
                let number = u64::from_le_bytes(
                    record_body[16..24]
                        .try_into()
                        .map_err(|_| "failed to read syscall number".to_string())?,
                );
                let result = i64::from_le_bytes(
                    record_body[24..32]
                        .try_into()
                        .map_err(|_| "failed to read syscall result".to_string())?,
                );
                events.push(TraceEvent::SyscallExit {
                    event_id,
                    tid,
                    number,
                    result,
                });
            }
            other => {
                return Err(format!("unknown event kind {}", other));
            }
        }

        expected_event_id += 1;
    }

    if offset != footer_start {
        return Err("event records boundary did not align with footer".to_string());
    }

    if (events.len() as u64) != expected_event_count {
        return Err(format!(
            "event count mismatch: footer specifies {}, but parsed {}",
            expected_event_count,
            events.len()
        ));
    }

    // 4. Validate Structural Syscall Pairing
    validate_syscall_pairing(&events)?;

    Ok(events)
}

/// Validates that entry/exit pairs in a single trace remain matched.
fn validate_syscall_pairing(events: &[TraceEvent]) -> Result<(), String> {
    let mut pending: HashMap<u32, u64> = HashMap::new();

    for event in events {
        match event {
            TraceEvent::SyscallEnter {
                event_id,
                tid,
                number,
                ..
            } => {
                if let Some(prev_nr) = pending.insert(*tid, *number) {
                    return Err(format!(
                        "structural pairing error at event {}: SyscallEnter nr={} on tid {} while previous nr={} is pending",
                        event_id, number, tid, prev_nr
                    ));
                }
            }
            TraceEvent::SyscallExit {
                event_id,
                tid,
                number,
                ..
            } => match pending.remove(tid) {
                Some(prev_nr) => {
                    if prev_nr != *number {
                        return Err(format!(
                            "structural pairing error at event {}: SyscallExit nr={} on tid {} does not match pending nr={}",
                            event_id, number, tid, prev_nr
                        ));
                    }
                }
                None => {
                    return Err(format!(
                        "structural pairing error at event {}: SyscallExit nr={} on tid {} with no pending SyscallEnter",
                        event_id, number, tid
                    ));
                }
            },
        }
    }

    Ok(())
}

/// Parses a trace file from disk and prints its human-readable dump to stdout.
pub fn dump_trace<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let path_ref = path.as_ref();
    let mut file = File::open(path_ref)
        .map_err(|e| format!("cannot open trace '{}': {}", path_ref.display(), e))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read trace '{}': {}", path_ref.display(), e))?;

    let events = parse_trace_bytes(&bytes)?;

    for event in events {
        match event {
            TraceEvent::SyscallEnter {
                event_id,
                tid,
                number,
                args,
            } => {
                println!(
                    "{:06} syscall-enter tid={} nr={} args=[{}, {}, {}, {}, {}, {}]",
                    event_id, tid, number, args[0], args[1], args[2], args[3], args[4], args[5]
                );
            }
            TraceEvent::SyscallExit {
                event_id,
                tid,
                number,
                result,
            } => {
                println!(
                    "{:06} syscall-exit  tid={} nr={} result={}",
                    event_id, tid, number, result
                );
            }
        }
    }

    Ok(())
}
