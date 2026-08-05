use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Fixed 8-byte trace header magic: "CAUSAL\0\0"
pub const TRACE_HEADER_MAGIC: &[u8; 8] = b"CAUSAL\0\0";

/// Fixed 8-byte trace footer magic: "CAUSEND\0"
pub const TRACE_FOOTER_MAGIC: &[u8; 8] = b"CAUSEND\0";

/// Trace format version 1.
pub const TRACE_VERSION_1: u32 = 1;

/// Trace format version 2 (with KernelMemoryWrite support).
pub const TRACE_VERSION_2: u32 = 2;

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

/// Event kind identifier for KernelMemoryWrite (V2).
pub const EVENT_KIND_KERNEL_MEMORY_WRITE: u8 = 3;

/// Fixed record length for SyscallEnter (excluding 4-byte length prefix).
pub const RECORD_LEN_SYSCALL_ENTER: u32 = 72;

/// Fixed record length for SyscallExit (excluding 4-byte length prefix).
pub const RECORD_LEN_SYSCALL_EXIT: u32 = 32;

/// Fixed header length in body for KernelMemoryWrite (excluding 4-byte length prefix and variable data).
pub const RECORD_LEN_KERNEL_MEMORY_WRITE_HEADER: u32 = 40;

/// Total size of trace header in bytes.
pub const HEADER_SIZE: usize = 16;

/// Total size of trace footer in bytes.
pub const FOOTER_SIZE: usize = 16;

/// Known Linux x86-64 syscall numbers.
pub const SYS_READ_X86_64: u64 = 0;
pub const SYS_GETPID_X86_64: u64 = 39;
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
    KernelMemoryWrite {
        event_id: u64,
        tid: u32,
        source_event_id: u64,
        recorded_address: u64,
        data: Vec<u8>,
    },
}

impl TraceEvent {
    pub fn event_id(&self) -> u64 {
        match self {
            TraceEvent::SyscallEnter { event_id, .. } => *event_id,
            TraceEvent::SyscallExit { event_id, .. } => *event_id,
            TraceEvent::KernelMemoryWrite { event_id, .. } => *event_id,
        }
    }

    pub fn tid(&self) -> u32 {
        match self {
            TraceEvent::SyscallEnter { tid, .. } => *tid,
            TraceEvent::SyscallExit { tid, .. } => *tid,
            TraceEvent::KernelMemoryWrite { tid, .. } => *tid,
        }
    }

    pub fn syscall_number(&self) -> Option<u64> {
        match self {
            TraceEvent::SyscallEnter { number, .. } => Some(*number),
            TraceEvent::SyscallExit { number, .. } => Some(*number),
            TraceEvent::KernelMemoryWrite { .. } => None,
        }
    }
}

/// Parsed trace file containing format version and event sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTrace {
    pub version: u32,
    pub events: Vec<TraceEvent>,
}

impl std::ops::Deref for ParsedTrace {
    type Target = [TraceEvent];

    fn deref(&self) -> &Self::Target {
        &self.events
    }
}

/// Streaming trace writer that encodes V1 or V2 binary format directly to an `io::Write` sink.
pub struct TraceWriter<W: Write> {
    writer: W,
    version: u32,
    next_event_id: u64,
    event_count: u64,
    finished: bool,
}

impl<W: Write> TraceWriter<W> {
    /// Creates a new `TraceWriter` defaulting to Trace Format V2 for production recording.
    pub fn new(writer: W) -> Result<Self, io::Error> {
        Self::new_v2(writer)
    }

    /// Creates a `TraceWriter` explicitly with Version 1 format.
    pub fn new_v1(writer: W) -> Result<Self, io::Error> {
        Self::new_with_version(writer, TRACE_VERSION_1)
    }

    /// Creates a `TraceWriter` explicitly with Version 2 format.
    pub fn new_v2(writer: W) -> Result<Self, io::Error> {
        Self::new_with_version(writer, TRACE_VERSION_2)
    }

    /// Creates a `TraceWriter` with the specified format version and writes the 16-byte header immediately.
    pub fn new_with_version(mut writer: W, version: u32) -> Result<Self, io::Error> {
        if version != TRACE_VERSION_1 && version != TRACE_VERSION_2 {
            return Err(io::Error::other(format!(
                "unsupported writer trace version: {}",
                version
            )));
        }

        let mut header = [0_u8; HEADER_SIZE];
        header[0..8].copy_from_slice(TRACE_HEADER_MAGIC);
        header[8..12].copy_from_slice(&version.to_le_bytes());
        header[12..14].copy_from_slice(&ARCH_X86_64.to_le_bytes());
        header[14] = BYTE_ORDER_LITTLE_ENDIAN;
        header[15] = POINTER_WIDTH_64;

        writer.write_all(&header)?;

        Ok(Self {
            writer,
            version,
            next_event_id: 1,
            event_count: 0,
            finished: false,
        })
    }

    pub fn version(&self) -> u32 {
        self.version
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

    /// Encodes and writes a `KernelMemoryWrite` event record (V2 only).
    pub fn write_kernel_memory_write(
        &mut self,
        tid: u32,
        source_event_id: u64,
        recorded_address: u64,
        data: &[u8],
    ) -> Result<u64, io::Error> {
        if self.finished {
            return Err(io::Error::other(
                "cannot write event to finished trace writer",
            ));
        }
        if self.version < TRACE_VERSION_2 {
            return Err(io::Error::other(
                "cannot write KernelMemoryWrite in trace format V1",
            ));
        }

        let data_len = match u32::try_from(data.len()) {
            Ok(len) => len,
            Err(_) => {
                return Err(io::Error::other("data length exceeds u32::MAX"));
            }
        };

        let record_len = RECORD_LEN_KERNEL_MEMORY_WRITE_HEADER
            .checked_add(data_len)
            .ok_or_else(|| io::Error::other("record length overflow in KernelMemoryWrite"))?;

        let event_id = self.next_event_id;
        let mut header_buf = [0_u8; 4 + RECORD_LEN_KERNEL_MEMORY_WRITE_HEADER as usize];

        // 4-byte record length prefix
        header_buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        // Event header (kind=3 + 3 reserved bytes)
        header_buf[4] = EVENT_KIND_KERNEL_MEMORY_WRITE;
        header_buf[5..8].copy_from_slice(&[0_u8; 3]);
        // Event metadata
        header_buf[8..16].copy_from_slice(&event_id.to_le_bytes());
        header_buf[16..20].copy_from_slice(&tid.to_le_bytes());
        // Memory payload header
        header_buf[20..28].copy_from_slice(&source_event_id.to_le_bytes());
        header_buf[28..36].copy_from_slice(&recorded_address.to_le_bytes());
        header_buf[36..40].copy_from_slice(&data_len.to_le_bytes());
        header_buf[40..44].copy_from_slice(&0_u32.to_le_bytes()); // payload_reserved = 0

        self.writer.write_all(&header_buf)?;
        self.writer.write_all(data)?;

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

/// Parses raw trace bytes into a validated `ParsedTrace` object.
pub fn parse_trace_bytes(bytes: &[u8]) -> Result<ParsedTrace, String> {
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
    if version != TRACE_VERSION_1 && version != TRACE_VERSION_2 {
        return Err(format!(
            "unsupported trace format version {}; supported versions: 1, 2",
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
            EVENT_KIND_KERNEL_MEMORY_WRITE => {
                if version < TRACE_VERSION_2 {
                    return Err(
                        "KernelMemoryWrite event kind 3 is not supported in trace format V1"
                            .to_string(),
                    );
                }
                if record_len < RECORD_LEN_KERNEL_MEMORY_WRITE_HEADER as usize {
                    return Err(format!(
                        "trace event {}: KernelMemoryWrite record length {} is smaller than minimum header {}",
                        event_id, record_len, RECORD_LEN_KERNEL_MEMORY_WRITE_HEADER
                    ));
                }
                let source_event_id = u64::from_le_bytes(
                    record_body[16..24]
                        .try_into()
                        .map_err(|_| "failed to read source_event_id".to_string())?,
                );
                let recorded_address = u64::from_le_bytes(
                    record_body[24..32]
                        .try_into()
                        .map_err(|_| "failed to read recorded_address".to_string())?,
                );
                let data_len = u32::from_le_bytes(
                    record_body[32..36]
                        .try_into()
                        .map_err(|_| "failed to read data_len".to_string())?,
                ) as usize;
                let payload_reserved = u32::from_le_bytes(
                    record_body[36..40]
                        .try_into()
                        .map_err(|_| "failed to read payload_reserved".to_string())?,
                );
                if payload_reserved != 0 {
                    return Err(format!(
                        "trace event {}: nonzero payload_reserved in KernelMemoryWrite: {}",
                        event_id, payload_reserved
                    ));
                }

                if record_len != RECORD_LEN_KERNEL_MEMORY_WRITE_HEADER as usize + data_len {
                    return Err(format!(
                        "trace event {}: record length {} does not match 40 + data_len ({})",
                        event_id, record_len, data_len
                    ));
                }

                let data = record_body[40..40 + data_len].to_vec();
                events.push(TraceEvent::KernelMemoryWrite {
                    event_id,
                    tid,
                    source_event_id,
                    recorded_address,
                    data,
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

    // 4. Validate Structural Syscall Pairing and Memory Event Invariants
    validate_trace_structure(version, &events)?;

    Ok(ParsedTrace { version, events })
}

/// Validates structural pairing and semantic memory-event invariants.
fn validate_trace_structure(version: u32, events: &[TraceEvent]) -> Result<(), String> {
    let mut pending: HashMap<u32, (u64, [u64; 6], u64)> = HashMap::new();
    // Tracks positive SYS_read exit awaiting its required KernelMemoryWrite: (tid, number, result, exit_event_id, enter_buf_addr)
    let mut pending_read_exit: Option<(u32, u64, i64, u64, u64)> = None;

    for event in events {
        match event {
            TraceEvent::SyscallEnter {
                event_id,
                tid,
                number,
                args,
            } => {
                if let Some((_, _, _, prev_exit_id, _)) = pending_read_exit.take() {
                    if version >= TRACE_VERSION_2 {
                        return Err(format!(
                            "positive SYS_read at exit event {} missing required KernelMemoryWrite event",
                            prev_exit_id
                        ));
                    }
                }

                if let Some((prev_nr, _, _)) = pending.insert(*tid, (*number, *args, *event_id)) {
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
                result,
            } => {
                if let Some((_, _, _, prev_exit_id, _)) = pending_read_exit.take() {
                    if version >= TRACE_VERSION_2 {
                        return Err(format!(
                            "positive SYS_read at exit event {} missing required KernelMemoryWrite event",
                            prev_exit_id
                        ));
                    }
                }

                match pending.remove(tid) {
                    Some((prev_nr, enter_args, _)) => {
                        if prev_nr != *number {
                            return Err(format!(
                                "structural pairing error at event {}: SyscallExit nr={} on tid {} does not match pending nr={}",
                                event_id, number, tid, prev_nr
                            ));
                        }

                        if *number == SYS_READ_X86_64 && *result > 0 {
                            if (*result as u64) > enter_args[2] {
                                return Err(format!(
                                    "trace event {}: SYS_read result {} exceeds requested count {}",
                                    event_id, result, enter_args[2]
                                ));
                            }
                            pending_read_exit =
                                Some((*tid, *number, *result, *event_id, enter_args[1]));
                        }
                    }
                    None => {
                        return Err(format!(
                            "structural pairing error at event {}: SyscallExit nr={} on tid {} with no pending SyscallEnter",
                            event_id, number, tid
                        ));
                    }
                }
            }
            TraceEvent::KernelMemoryWrite {
                event_id,
                tid,
                source_event_id,
                recorded_address,
                data,
            } => match pending_read_exit.take() {
                Some((exit_tid, exit_nr, exit_result, exit_event_id, enter_buf_addr)) => {
                    if exit_tid != *tid {
                        return Err(format!(
                            "trace event {}: KernelMemoryWrite tid {} does not match source exit tid {}",
                            event_id, tid, exit_tid
                        ));
                    }
                    if *source_event_id != exit_event_id {
                        return Err(format!(
                            "trace event {}: KernelMemoryWrite source_event_id {} does not match immediately preceding exit event {}",
                            event_id, source_event_id, exit_event_id
                        ));
                    }
                    if exit_nr != SYS_READ_X86_64 {
                        return Err(format!(
                            "trace event {}: KernelMemoryWrite source exit is nr={}, expected SYS_read ({})",
                            event_id, exit_nr, SYS_READ_X86_64
                        ));
                    }
                    if exit_result <= 0 {
                        return Err(format!(
                            "trace event {}: KernelMemoryWrite attached to non-positive read result {}",
                            event_id, exit_result
                        ));
                    }
                    if data.len() != exit_result as usize {
                        return Err(format!(
                            "trace event {}: KernelMemoryWrite data length {} does not match read result {}",
                            event_id,
                            data.len(),
                            exit_result
                        ));
                    }
                    if *recorded_address != enter_buf_addr {
                        return Err(format!(
                            "trace event {}: KernelMemoryWrite recorded_address 0x{:x} does not match read entry buffer address 0x{:x}",
                            event_id, recorded_address, enter_buf_addr
                        ));
                    }
                }
                None => {
                    if *event_id > 1 {
                        let prev_idx = (*event_id as usize) - 2;
                        if let Some(prev_event) = events.get(prev_idx) {
                            match prev_event {
                                TraceEvent::SyscallEnter { .. } => {
                                    return Err(format!(
                                        "trace event {}: KernelMemoryWrite source_event_id {} points to a SyscallEnter, expected SyscallExit",
                                        event_id, source_event_id
                                    ));
                                }
                                TraceEvent::SyscallExit {
                                    number,
                                    result,
                                    event_id: prev_id,
                                    ..
                                } => {
                                    if *number != SYS_READ_X86_64 {
                                        return Err(format!(
                                            "trace event {}: KernelMemoryWrite attached to SyscallExit nr={}, expected SYS_read ({})",
                                            event_id, number, SYS_READ_X86_64
                                        ));
                                    }
                                    if *result == 0 {
                                        return Err(format!(
                                            "trace event {}: KernelMemoryWrite attached to zero-result read exit event {}",
                                            event_id, prev_id
                                        ));
                                    }
                                    if *result < 0 {
                                        return Err(format!(
                                            "trace event {}: KernelMemoryWrite attached to failed read exit event {} (result={})",
                                            event_id, prev_id, result
                                        ));
                                    }
                                }
                                TraceEvent::KernelMemoryWrite { .. } => {}
                            }
                        }
                    }
                    return Err(format!(
                        "trace event {}: KernelMemoryWrite does not immediately follow a positive SYS_read exit",
                        event_id
                    ));
                }
            },
        }
    }

    if let Some((_, _, _, exit_id, _)) = pending_read_exit {
        if version >= TRACE_VERSION_2 {
            return Err(format!(
                "positive SYS_read at exit event {} at end of trace missing required KernelMemoryWrite event",
                exit_id
            ));
        }
    }

    Ok(())
}

/// Reads a trace file from disk and parses its binary format into a validated `ParsedTrace` object.
pub fn read_trace_file_versioned<P: AsRef<Path>>(path: P) -> Result<ParsedTrace, String> {
    let path_ref = path.as_ref();
    let mut file = File::open(path_ref)
        .map_err(|e| format!("cannot open trace '{}': {}", path_ref.display(), e))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read trace '{}': {}", path_ref.display(), e))?;

    parse_trace_bytes(&bytes)
}

/// Reads a trace file from disk and returns its validated event list (compatible with V1 and V2).
pub fn read_trace_file<P: AsRef<Path>>(path: P) -> Result<Vec<TraceEvent>, String> {
    Ok(read_trace_file_versioned(path)?.events)
}

/// Parses a trace file from disk and prints its human-readable dump to stdout.
pub fn dump_trace<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let parsed = read_trace_file_versioned(path)?;

    for event in parsed.events {
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
            TraceEvent::KernelMemoryWrite {
                event_id,
                tid,
                source_event_id,
                recorded_address,
                data,
            } => {
                let hex_preview: String = if data.len() <= 32 {
                    data.iter().map(|b| format!("{:02x}", b)).collect()
                } else {
                    let prefix: String = data[..16].iter().map(|b| format!("{:02x}", b)).collect();
                    format!("{}...", prefix)
                };
                println!(
                    "{:06} kernel-memory-write tid={} source={:06} addr=0x{:x} len={} data_hex={}",
                    event_id,
                    tid,
                    source_event_id,
                    recorded_address,
                    data.len(),
                    hex_preview
                );
            }
        }
    }

    Ok(())
}
