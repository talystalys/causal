use crate::maps::{validate_regions_canonical_order, MemoryMapModel, MemoryRegion};
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

/// Trace format version 3 (with virtual memory map model support).
pub const TRACE_VERSION_3: u32 = 3;

/// Trace format version 4 (with signal delivery and siginfo support).
pub const TRACE_VERSION_4: u32 = 4;

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

/// Event kind identifier for MemoryMapSnapshot (V3).
pub const EVENT_KIND_MEMORY_MAP_SNAPSHOT: u8 = 4;

/// Event kind identifier for MemoryMapAdd (V3).
pub const EVENT_KIND_MEMORY_MAP_ADD: u8 = 5;

/// Event kind identifier for MemoryMapRemove (V3).
pub const EVENT_KIND_MEMORY_MAP_REMOVE: u8 = 6;

/// Event kind identifier for SignalDelivery (V4).
pub const EVENT_KIND_SIGNAL_DELIVERY: u8 = 7;

/// Fixed record length for SyscallEnter (excluding 4-byte length prefix).
pub const RECORD_LEN_SYSCALL_ENTER: u32 = 72;

/// Fixed record length for SyscallExit (excluding 4-byte length prefix).
pub const RECORD_LEN_SYSCALL_EXIT: u32 = 32;

/// Fixed header length in body for KernelMemoryWrite (excluding 4-byte length prefix and variable data).
pub const RECORD_LEN_KERNEL_MEMORY_WRITE_HEADER: u32 = 40;

/// Fixed descriptor length for MemoryRegion header (excluding variable label).
pub const DESCRIPTOR_LEN_REGION_HEADER: usize = 48;

/// Fixed header length in body for SignalDelivery (excluding 4-byte length prefix and siginfo bytes).
pub const RECORD_LEN_SIGNAL_DELIVERY_HEADER: u32 = 32;

/// Standard x86-64 Linux siginfo_t size in bytes.
pub const SIGINFO_SIZE_X86_64: usize = 128;

/// Total size of trace header in bytes.
pub const HEADER_SIZE: usize = 16;

/// Total size of trace footer in bytes.
pub const FOOTER_SIZE: usize = 16;

/// Known Linux x86-64 syscall numbers.
pub const SYS_READ_X86_64: u64 = 0;
pub const SYS_MMAP_X86_64: u64 = 9;
pub const SYS_MPROTECT_X86_64: u64 = 10;
pub const SYS_MUNMAP_X86_64: u64 = 11;
pub const SYS_BRK_X86_64: u64 = 12;
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
    MemoryMapSnapshot {
        event_id: u64,
        tid: u32,
        regions: Vec<MemoryRegion>,
    },
    MemoryMapAdd {
        event_id: u64,
        tid: u32,
        source_event_id: u64,
        region: MemoryRegion,
    },
    MemoryMapRemove {
        event_id: u64,
        tid: u32,
        source_event_id: u64,
        region: MemoryRegion,
    },
    SignalDelivery {
        event_id: u64,
        tid: u32,
        signal_number: i32,
        si_errno: i32,
        si_code: i32,
        siginfo_bytes: Vec<u8>,
    },
}

impl TraceEvent {
    pub fn event_id(&self) -> u64 {
        match self {
            TraceEvent::SyscallEnter { event_id, .. } => *event_id,
            TraceEvent::SyscallExit { event_id, .. } => *event_id,
            TraceEvent::KernelMemoryWrite { event_id, .. } => *event_id,
            TraceEvent::MemoryMapSnapshot { event_id, .. } => *event_id,
            TraceEvent::MemoryMapAdd { event_id, .. } => *event_id,
            TraceEvent::MemoryMapRemove { event_id, .. } => *event_id,
            TraceEvent::SignalDelivery { event_id, .. } => *event_id,
        }
    }

    pub fn tid(&self) -> u32 {
        match self {
            TraceEvent::SyscallEnter { tid, .. } => *tid,
            TraceEvent::SyscallExit { tid, .. } => *tid,
            TraceEvent::KernelMemoryWrite { tid, .. } => *tid,
            TraceEvent::MemoryMapSnapshot { tid, .. } => *tid,
            TraceEvent::MemoryMapAdd { tid, .. } => *tid,
            TraceEvent::MemoryMapRemove { tid, .. } => *tid,
            TraceEvent::SignalDelivery { tid, .. } => *tid,
        }
    }

    pub fn syscall_number(&self) -> Option<u64> {
        match self {
            TraceEvent::SyscallEnter { number, .. } => Some(*number),
            TraceEvent::SyscallExit { number, .. } => Some(*number),
            TraceEvent::KernelMemoryWrite { .. } => None,
            TraceEvent::MemoryMapSnapshot { .. } => None,
            TraceEvent::MemoryMapAdd { .. } => None,
            TraceEvent::MemoryMapRemove { .. } => None,
            TraceEvent::SignalDelivery { .. } => None,
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

/// Helper function to encode a single MemoryRegion descriptor to bytes.
pub fn encode_region_descriptor(region: &MemoryRegion, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&region.start.to_le_bytes());
    buf.extend_from_slice(&region.end.to_le_bytes());
    buf.extend_from_slice(&region.file_offset.to_le_bytes());
    buf.extend_from_slice(&region.inode.to_le_bytes());
    buf.extend_from_slice(&region.dev_major.to_le_bytes());
    buf.extend_from_slice(&region.dev_minor.to_le_bytes());
    buf.push(region.prot_bits());
    buf.push(region.sharing_byte());
    buf.extend_from_slice(&[0_u8; 2]); // reserved = 0
    let label_len = region.label.len() as u32;
    buf.extend_from_slice(&label_len.to_le_bytes());
    buf.extend_from_slice(&region.label);
}

/// Helper function to decode a single MemoryRegion descriptor from bytes.
pub fn decode_region_descriptor(bytes: &[u8], offset: &mut usize) -> Result<MemoryRegion, String> {
    if *offset + DESCRIPTOR_LEN_REGION_HEADER > bytes.len() {
        return Err("truncated region descriptor header".to_string());
    }
    let start = u64::from_le_bytes(bytes[*offset..*offset + 8].try_into().unwrap());
    let end = u64::from_le_bytes(bytes[*offset + 8..*offset + 16].try_into().unwrap());
    let file_offset = u64::from_le_bytes(bytes[*offset + 16..*offset + 24].try_into().unwrap());
    let inode = u64::from_le_bytes(bytes[*offset + 24..*offset + 32].try_into().unwrap());
    let dev_major = u32::from_le_bytes(bytes[*offset + 32..*offset + 36].try_into().unwrap());
    let dev_minor = u32::from_le_bytes(bytes[*offset + 36..*offset + 40].try_into().unwrap());
    let prot_bits = bytes[*offset + 40];
    let sharing_byte = bytes[*offset + 41];
    let reserved = &bytes[*offset + 42..*offset + 44];
    if reserved != [0_u8; 2] {
        return Err(format!("nonzero descriptor reserved bytes: {:?}", reserved));
    }
    if prot_bits > 7 {
        return Err(format!("invalid prot bits {}", prot_bits));
    }
    let prot_read = (prot_bits & 1) != 0;
    let prot_write = (prot_bits & 2) != 0;
    let prot_exec = (prot_bits & 4) != 0;
    let shared = match sharing_byte {
        1 => false,
        2 => true,
        other => return Err(format!("invalid sharing byte {}", other)),
    };
    let label_len =
        u32::from_le_bytes(bytes[*offset + 44..*offset + 48].try_into().unwrap()) as usize;
    *offset += DESCRIPTOR_LEN_REGION_HEADER;
    if *offset + label_len > bytes.len() {
        return Err("label length extends past descriptor boundary".to_string());
    }
    let label = bytes[*offset..*offset + label_len].to_vec();
    *offset += label_len;

    let region = MemoryRegion {
        start,
        end,
        prot_read,
        prot_write,
        prot_exec,
        shared,
        file_offset,
        dev_major,
        dev_minor,
        inode,
        label,
    };
    region.validate()?;
    Ok(region)
}

/// Streaming trace writer that encodes V1, V2, V3, or V4 binary format directly to an `io::Write` sink.
pub struct TraceWriter<W: Write> {
    writer: W,
    version: u32,
    next_event_id: u64,
    event_count: u64,
    finished: bool,
}

impl<W: Write> TraceWriter<W> {
    /// Creates a new `TraceWriter` defaulting to Trace Format V4 for production recording.
    pub fn new(writer: W) -> Result<Self, io::Error> {
        Self::new_v4(writer)
    }

    /// Creates a `TraceWriter` explicitly with Version 1 format.
    pub fn new_v1(writer: W) -> Result<Self, io::Error> {
        Self::new_with_version(writer, TRACE_VERSION_1)
    }

    /// Creates a `TraceWriter` explicitly with Version 2 format.
    pub fn new_v2(writer: W) -> Result<Self, io::Error> {
        Self::new_with_version(writer, TRACE_VERSION_2)
    }

    /// Creates a `TraceWriter` explicitly with Version 3 format.
    pub fn new_v3(writer: W) -> Result<Self, io::Error> {
        Self::new_with_version(writer, TRACE_VERSION_3)
    }

    /// Creates a `TraceWriter` explicitly with Version 4 format.
    pub fn new_v4(writer: W) -> Result<Self, io::Error> {
        Self::new_with_version(writer, TRACE_VERSION_4)
    }

    /// Creates a `TraceWriter` with the specified format version and writes the 16-byte header immediately.
    pub fn new_with_version(mut writer: W, version: u32) -> Result<Self, io::Error> {
        if version != TRACE_VERSION_1
            && version != TRACE_VERSION_2
            && version != TRACE_VERSION_3
            && version != TRACE_VERSION_4
        {
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

    /// Encodes and writes a `KernelMemoryWrite` event record (V2+).
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

    /// Encodes and writes a `MemoryMapSnapshot` event record (V3+).
    pub fn write_memory_map_snapshot(
        &mut self,
        tid: u32,
        regions: &[MemoryRegion],
    ) -> Result<u64, io::Error> {
        if self.finished {
            return Err(io::Error::other(
                "cannot write event to finished trace writer",
            ));
        }
        if self.version < TRACE_VERSION_3 {
            return Err(io::Error::other(
                "cannot write MemoryMapSnapshot in trace format V1 or V2",
            ));
        }

        let mut descriptors_buf = Vec::new();
        for r in regions {
            encode_region_descriptor(r, &mut descriptors_buf);
        }

        let region_count = u32::try_from(regions.len())
            .map_err(|_| io::Error::other("region count exceeds u32::MAX"))?;
        let record_len = 24_u32
            .checked_add(descriptors_buf.len() as u32)
            .ok_or_else(|| io::Error::other("record length overflow in MemoryMapSnapshot"))?;

        let event_id = self.next_event_id;
        let mut header_buf = [0_u8; 28]; // 4-byte len + 24-byte header

        // 4-byte record length prefix
        header_buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        // Event header (kind=4 + 3 reserved bytes)
        header_buf[4] = EVENT_KIND_MEMORY_MAP_SNAPSHOT;
        header_buf[5..8].copy_from_slice(&[0_u8; 3]);
        // Event metadata
        header_buf[8..16].copy_from_slice(&event_id.to_le_bytes());
        header_buf[16..20].copy_from_slice(&tid.to_le_bytes());
        // Snapshot header
        header_buf[20..24].copy_from_slice(&region_count.to_le_bytes());
        header_buf[24..28].copy_from_slice(&0_u32.to_le_bytes()); // reserved = 0

        self.writer.write_all(&header_buf)?;
        self.writer.write_all(&descriptors_buf)?;

        self.next_event_id += 1;
        self.event_count += 1;
        Ok(event_id)
    }

    /// Encodes and writes a `MemoryMapAdd` event record (V3+).
    pub fn write_memory_map_add(
        &mut self,
        tid: u32,
        source_event_id: u64,
        region: &MemoryRegion,
    ) -> Result<u64, io::Error> {
        if self.finished {
            return Err(io::Error::other(
                "cannot write event to finished trace writer",
            ));
        }
        if self.version < TRACE_VERSION_3 {
            return Err(io::Error::other(
                "cannot write MemoryMapAdd in trace format V1 or V2",
            ));
        }

        let mut desc_buf = Vec::new();
        encode_region_descriptor(region, &mut desc_buf);

        let record_len = 24_u32
            .checked_add(desc_buf.len() as u32)
            .ok_or_else(|| io::Error::other("record length overflow in MemoryMapAdd"))?;

        let event_id = self.next_event_id;
        let mut header_buf = [0_u8; 28]; // 4-byte len + 24-byte header

        header_buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        header_buf[4] = EVENT_KIND_MEMORY_MAP_ADD;
        header_buf[5..8].copy_from_slice(&[0_u8; 3]);
        header_buf[8..16].copy_from_slice(&event_id.to_le_bytes());
        header_buf[16..20].copy_from_slice(&tid.to_le_bytes());
        header_buf[20..28].copy_from_slice(&source_event_id.to_le_bytes());

        self.writer.write_all(&header_buf)?;
        self.writer.write_all(&desc_buf)?;

        self.next_event_id += 1;
        self.event_count += 1;
        Ok(event_id)
    }

    /// Encodes and writes a `MemoryMapRemove` event record (V3+).
    pub fn write_memory_map_remove(
        &mut self,
        tid: u32,
        source_event_id: u64,
        region: &MemoryRegion,
    ) -> Result<u64, io::Error> {
        if self.finished {
            return Err(io::Error::other(
                "cannot write event to finished trace writer",
            ));
        }
        if self.version < TRACE_VERSION_3 {
            return Err(io::Error::other(
                "cannot write MemoryMapRemove in trace format V1 or V2",
            ));
        }

        let mut desc_buf = Vec::new();
        encode_region_descriptor(region, &mut desc_buf);

        let record_len = 24_u32
            .checked_add(desc_buf.len() as u32)
            .ok_or_else(|| io::Error::other("record length overflow in MemoryMapRemove"))?;

        let event_id = self.next_event_id;
        let mut header_buf = [0_u8; 28]; // 4-byte len + 24-byte header

        header_buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        header_buf[4] = EVENT_KIND_MEMORY_MAP_REMOVE;
        header_buf[5..8].copy_from_slice(&[0_u8; 3]);
        header_buf[8..16].copy_from_slice(&event_id.to_le_bytes());
        header_buf[16..20].copy_from_slice(&tid.to_le_bytes());
        header_buf[20..28].copy_from_slice(&source_event_id.to_le_bytes());

        self.writer.write_all(&header_buf)?;
        self.writer.write_all(&desc_buf)?;

        self.next_event_id += 1;
        self.event_count += 1;
        Ok(event_id)
    }

    /// Encodes and writes a `SignalDelivery` event record (V4+).
    pub fn write_signal_delivery(
        &mut self,
        tid: u32,
        signal_number: i32,
        si_errno: i32,
        si_code: i32,
        siginfo_bytes: &[u8],
    ) -> Result<u64, io::Error> {
        if self.finished {
            return Err(io::Error::other(
                "cannot write event to finished trace writer",
            ));
        }
        if self.version < TRACE_VERSION_4 {
            return Err(io::Error::other(
                "cannot write SignalDelivery in trace format V1, V2, or V3",
            ));
        }
        if siginfo_bytes.len() != SIGINFO_SIZE_X86_64 {
            return Err(io::Error::other(format!(
                "invalid siginfo bytes length {}; expected {}",
                siginfo_bytes.len(),
                SIGINFO_SIZE_X86_64
            )));
        }

        let siginfo_len = siginfo_bytes.len() as u32;
        let record_len = RECORD_LEN_SIGNAL_DELIVERY_HEADER
            .checked_add(siginfo_len)
            .ok_or_else(|| io::Error::other("record length overflow in SignalDelivery"))?;

        let event_id = self.next_event_id;
        let mut header_buf = [0_u8; 4 + RECORD_LEN_SIGNAL_DELIVERY_HEADER as usize];

        // 4-byte record length prefix
        header_buf[0..4].copy_from_slice(&record_len.to_le_bytes());
        // Event header (kind=7 + 3 reserved bytes)
        header_buf[4] = EVENT_KIND_SIGNAL_DELIVERY;
        header_buf[5..8].copy_from_slice(&[0_u8; 3]);
        // Event metadata
        header_buf[8..16].copy_from_slice(&event_id.to_le_bytes());
        header_buf[16..20].copy_from_slice(&tid.to_le_bytes());
        // Signal payload header
        header_buf[20..24].copy_from_slice(&signal_number.to_le_bytes());
        header_buf[24..28].copy_from_slice(&si_errno.to_le_bytes());
        header_buf[28..32].copy_from_slice(&si_code.to_le_bytes());
        header_buf[32..36].copy_from_slice(&siginfo_len.to_le_bytes());

        self.writer.write_all(&header_buf)?;
        self.writer.write_all(siginfo_bytes)?;

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
    if version != TRACE_VERSION_1
        && version != TRACE_VERSION_2
        && version != TRACE_VERSION_3
        && version != TRACE_VERSION_4
    {
        return Err(format!(
            "unsupported trace format version {}; supported versions: 1, 2, 3, 4",
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
            EVENT_KIND_MEMORY_MAP_SNAPSHOT => {
                if version < TRACE_VERSION_3 {
                    return Err(format!(
                        "MemoryMapSnapshot event kind 4 is not supported in trace format V{}",
                        version
                    ));
                }
                if record_len < 24 {
                    return Err(format!(
                        "trace event {}: MemoryMapSnapshot record length {} is smaller than minimum header 24",
                        event_id, record_len
                    ));
                }
                let region_count = u32::from_le_bytes(
                    record_body[16..20]
                        .try_into()
                        .map_err(|_| "failed to read region_count".to_string())?,
                ) as usize;
                let reserved = u32::from_le_bytes(
                    record_body[20..24]
                        .try_into()
                        .map_err(|_| "failed to read reserved".to_string())?,
                );
                if reserved != 0 {
                    return Err(format!(
                        "trace event {}: nonzero reserved in MemoryMapSnapshot: {}",
                        event_id, reserved
                    ));
                }

                let mut desc_offset = 24;
                let mut regions = Vec::with_capacity(region_count);
                for _ in 0..region_count {
                    let region = decode_region_descriptor(record_body, &mut desc_offset)?;
                    regions.push(region);
                }

                if desc_offset != record_body.len() {
                    return Err(format!(
                        "trace event {}: trailing garbage in MemoryMapSnapshot record (parsed {} bytes, body len {})",
                        event_id, desc_offset, record_body.len()
                    ));
                }

                // Verify regions form a valid canonical snapshot (must already be sorted and non-overlapping)
                validate_regions_canonical_order(&regions)?;

                events.push(TraceEvent::MemoryMapSnapshot {
                    event_id,
                    tid,
                    regions,
                });
            }
            EVENT_KIND_MEMORY_MAP_ADD => {
                if version < TRACE_VERSION_3 {
                    return Err(format!(
                        "MemoryMapAdd event kind 5 is not supported in trace format V{}",
                        version
                    ));
                }
                if record_len < 24 + DESCRIPTOR_LEN_REGION_HEADER {
                    return Err(format!(
                        "trace event {}: MemoryMapAdd record length {} is smaller than minimum header",
                        event_id, record_len
                    ));
                }
                let source_event_id = u64::from_le_bytes(
                    record_body[16..24]
                        .try_into()
                        .map_err(|_| "failed to read source_event_id".to_string())?,
                );
                let mut desc_offset = 24;
                let region = decode_region_descriptor(record_body, &mut desc_offset)?;
                if desc_offset != record_body.len() {
                    return Err(format!(
                        "trace event {}: trailing garbage in MemoryMapAdd record",
                        event_id
                    ));
                }

                events.push(TraceEvent::MemoryMapAdd {
                    event_id,
                    tid,
                    source_event_id,
                    region,
                });
            }
            EVENT_KIND_MEMORY_MAP_REMOVE => {
                if version < TRACE_VERSION_3 {
                    return Err(format!(
                        "MemoryMapRemove event kind 6 is not supported in trace format V{}",
                        version
                    ));
                }
                if record_len < 24 + DESCRIPTOR_LEN_REGION_HEADER {
                    return Err(format!(
                        "trace event {}: MemoryMapRemove record length {} is smaller than minimum header",
                        event_id, record_len
                    ));
                }
                let source_event_id = u64::from_le_bytes(
                    record_body[16..24]
                        .try_into()
                        .map_err(|_| "failed to read source_event_id".to_string())?,
                );
                let mut desc_offset = 24;
                let region = decode_region_descriptor(record_body, &mut desc_offset)?;
                if desc_offset != record_body.len() {
                    return Err(format!(
                        "trace event {}: trailing garbage in MemoryMapRemove record",
                        event_id
                    ));
                }

                events.push(TraceEvent::MemoryMapRemove {
                    event_id,
                    tid,
                    source_event_id,
                    region,
                });
            }
            EVENT_KIND_SIGNAL_DELIVERY => {
                if version < TRACE_VERSION_4 {
                    return Err(format!(
                        "SignalDelivery event kind 7 is not supported in trace format V{}",
                        version
                    ));
                }
                if record_len < RECORD_LEN_SIGNAL_DELIVERY_HEADER as usize {
                    return Err(format!(
                        "trace event {}: SignalDelivery record length {} is smaller than minimum header {}",
                        event_id, record_len, RECORD_LEN_SIGNAL_DELIVERY_HEADER
                    ));
                }
                let signal_number = i32::from_le_bytes(
                    record_body[16..20]
                        .try_into()
                        .map_err(|_| "failed to read signal_number".to_string())?,
                );
                if signal_number <= 0 || signal_number > 64 {
                    return Err(format!(
                        "trace event {}: invalid signal number {}",
                        event_id, signal_number
                    ));
                }
                let si_errno = i32::from_le_bytes(
                    record_body[20..24]
                        .try_into()
                        .map_err(|_| "failed to read si_errno".to_string())?,
                );
                let si_code = i32::from_le_bytes(
                    record_body[24..28]
                        .try_into()
                        .map_err(|_| "failed to read si_code".to_string())?,
                );
                let siginfo_len = u32::from_le_bytes(
                    record_body[28..32]
                        .try_into()
                        .map_err(|_| "failed to read siginfo_len".to_string())?,
                ) as usize;

                if siginfo_len != SIGINFO_SIZE_X86_64 {
                    return Err(format!(
                        "trace event {}: invalid siginfo_len {}, expected {}",
                        event_id, siginfo_len, SIGINFO_SIZE_X86_64
                    ));
                }
                if record_len != (RECORD_LEN_SIGNAL_DELIVERY_HEADER as usize + siginfo_len) {
                    return Err(format!(
                        "trace event {}: record length {} does not match 32 + siginfo_len ({})",
                        event_id, record_len, siginfo_len
                    ));
                }

                let siginfo_bytes = record_body[32..32 + siginfo_len].to_vec();

                // Validate raw siginfo common fields match explicit header fields
                let raw_signo = i32::from_le_bytes(
                    siginfo_bytes[0..4]
                        .try_into()
                        .map_err(|_| "failed to read raw si_signo".to_string())?,
                );
                let raw_errno = i32::from_le_bytes(
                    siginfo_bytes[4..8]
                        .try_into()
                        .map_err(|_| "failed to read raw si_errno".to_string())?,
                );
                let raw_code = i32::from_le_bytes(
                    siginfo_bytes[8..12]
                        .try_into()
                        .map_err(|_| "failed to read raw si_code".to_string())?,
                );

                if raw_signo != signal_number {
                    return Err(format!(
                        "trace event {}: raw siginfo si_signo {} does not match explicit signal_number {}",
                        event_id, raw_signo, signal_number
                    ));
                }
                if raw_errno != si_errno {
                    return Err(format!(
                        "trace event {}: raw siginfo si_errno {} does not match explicit si_errno {}",
                        event_id, raw_errno, si_errno
                    ));
                }
                if raw_code != si_code {
                    return Err(format!(
                        "trace event {}: raw siginfo si_code {} does not match explicit si_code {}",
                        event_id, raw_code, si_code
                    ));
                }

                events.push(TraceEvent::SignalDelivery {
                    event_id,
                    tid,
                    signal_number,
                    si_errno,
                    si_code,
                    siginfo_bytes,
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

    // 4. Validate Structural Syscall Pairing, Memory Events, and V3 Memory Map Invariants
    validate_trace_structure(version, &events)?;

    Ok(ParsedTrace { version, events })
}

/// Validates structural pairing, memory-event invariants, and V3 memory-map model invariants.
fn validate_trace_structure(version: u32, events: &[TraceEvent]) -> Result<(), String> {
    let mut pending: HashMap<u32, (u64, [u64; 6], u64)> = HashMap::new();
    // Tracks positive SYS_read exit awaiting its required KernelMemoryWrite: (tid, number, result, exit_event_id, enter_buf_addr)
    let mut pending_read_exit: Option<(u32, u64, i64, u64, u64)> = None;

    // V3 map validation state
    let mut snapshot_seen = false;
    let mut current_map_model: Option<MemoryMapModel> = None;
    // Map of exit_event_id -> syscall_number
    let mut exit_syscall_map: HashMap<u64, u64> = HashMap::new();
    // Tracks current delta source grouping: Option<(source_event_id, seen_add)>
    let mut current_delta_group: Option<(u64, bool)> = None;
    let mut last_syscall_exit_id: Option<u64> = None;

    for (idx, event) in events.iter().enumerate() {
        match event {
            TraceEvent::MemoryMapSnapshot {
                event_id, regions, ..
            } => {
                last_syscall_exit_id = None;
                if version < TRACE_VERSION_3 {
                    return Err(format!(
                        "MemoryMapSnapshot event in trace format V{}",
                        version
                    ));
                }
                if snapshot_seen {
                    return Err(format!(
                        "duplicate MemoryMapSnapshot event {} in V3 trace",
                        event_id
                    ));
                }
                if idx != 0 {
                    return Err(format!(
                        "MemoryMapSnapshot event {} must be the first event in a V3 trace",
                        event_id
                    ));
                }
                snapshot_seen = true;
                current_map_model = Some(MemoryMapModel::from_canonical_regions(regions.clone())?);
            }
            TraceEvent::SyscallEnter {
                event_id,
                tid,
                number,
                args,
            } => {
                current_delta_group = None;
                last_syscall_exit_id = None;
                if version >= TRACE_VERSION_3 && !snapshot_seen {
                    return Err(format!(
                        "V3 trace missing initial MemoryMapSnapshot before SyscallEnter event {}",
                        event_id
                    ));
                }

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
                current_delta_group = None;
                last_syscall_exit_id = Some(*event_id);
                exit_syscall_map.insert(*event_id, *number);

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
                                _ => {}
                            }
                        }
                    }
                    return Err(format!(
                        "trace event {}: KernelMemoryWrite does not immediately follow a positive SYS_read exit",
                        event_id
                    ));
                }
            },
            TraceEvent::MemoryMapRemove {
                event_id,
                source_event_id,
                region,
                ..
            } => {
                if last_syscall_exit_id != Some(*source_event_id) {
                    return Err(format!(
                        "trace event {}: MemoryMapRemove source_event_id {} is not contiguous with triggering SyscallExit",
                        event_id, source_event_id
                    ));
                }

                let source_nr = match exit_syscall_map.get(source_event_id) {
                    Some(nr) => *nr,
                    None => {
                        return Err(format!(
                            "trace event {}: MemoryMapRemove source_event_id {} is not an existing SyscallExit",
                            event_id, source_event_id
                        ));
                    }
                };
                if source_nr != SYS_MMAP_X86_64
                    && source_nr != SYS_MPROTECT_X86_64
                    && source_nr != SYS_MUNMAP_X86_64
                    && source_nr != SYS_BRK_X86_64
                {
                    return Err(format!(
                        "trace event {}: MemoryMapRemove sourced by non-mapping syscall nr={}",
                        event_id, source_nr
                    ));
                }

                // Check delta group ordering (removes must precede adds for same source)
                match current_delta_group {
                    Some((group_source, seen_add)) => {
                        if group_source != *source_event_id {
                            current_delta_group = Some((*source_event_id, false));
                        } else if seen_add {
                            return Err(format!(
                                "trace event {}: MemoryMapRemove emitted after MemoryMapAdd for source event {}",
                                event_id, source_event_id
                            ));
                        }
                    }
                    None => {
                        current_delta_group = Some((*source_event_id, false));
                    }
                }

                if let Some(model) = current_map_model.as_mut() {
                    model.apply_remove(region)?;
                }
            }
            TraceEvent::MemoryMapAdd {
                event_id,
                source_event_id,
                region,
                ..
            } => {
                if last_syscall_exit_id != Some(*source_event_id) {
                    return Err(format!(
                        "trace event {}: MemoryMapAdd source_event_id {} is not contiguous with triggering SyscallExit",
                        event_id, source_event_id
                    ));
                }

                let source_nr = match exit_syscall_map.get(source_event_id) {
                    Some(nr) => *nr,
                    None => {
                        return Err(format!(
                            "trace event {}: MemoryMapAdd source_event_id {} is not an existing SyscallExit",
                            event_id, source_event_id
                        ));
                    }
                };
                if source_nr != SYS_MMAP_X86_64
                    && source_nr != SYS_MPROTECT_X86_64
                    && source_nr != SYS_MUNMAP_X86_64
                    && source_nr != SYS_BRK_X86_64
                {
                    return Err(format!(
                        "trace event {}: MemoryMapAdd sourced by non-mapping syscall nr={}",
                        event_id, source_nr
                    ));
                }

                // Update delta group
                current_delta_group = Some((*source_event_id, true));

                if let Some(model) = current_map_model.as_mut() {
                    model.apply_add(region.clone())?;
                }
            }
            TraceEvent::SignalDelivery {
                event_id,
                signal_number,
                ..
            } => {
                if version >= TRACE_VERSION_3 && !snapshot_seen {
                    return Err(format!(
                        "V{} trace missing initial MemoryMapSnapshot before SignalDelivery event {}",
                        version, event_id
                    ));
                }
                if *signal_number <= 0 || *signal_number > 64 {
                    return Err(format!(
                        "trace event {}: invalid signal number {}",
                        event_id, signal_number
                    ));
                }
            }
        }
    }

    if version >= TRACE_VERSION_3 && !snapshot_seen {
        return Err(format!(
            "V{} trace is missing required initial MemoryMapSnapshot event",
            version
        ));
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

/// Reconstructs the historical virtual memory map model immediately after the specified `target_event_id`.
pub fn reconstruct_maps_at_event(
    parsed_trace: &ParsedTrace,
    target_event_id: u64,
) -> Result<MemoryMapModel, String> {
    if parsed_trace.version < TRACE_VERSION_3 {
        return Err(format!(
            "trace format V{} has no initial memory-map model; record again with V3",
            parsed_trace.version
        ));
    }
    if target_event_id == 0 {
        return Err("event-id must be non-zero".to_string());
    }

    let target_exists = parsed_trace
        .events
        .iter()
        .any(|e| e.event_id() == target_event_id);
    if !target_exists {
        return Err(format!(
            "event-id {} not found in trace (event count: {})",
            target_event_id,
            parsed_trace.events.len()
        ));
    }

    let mut model: Option<MemoryMapModel> = None;

    for event in &parsed_trace.events {
        match event {
            TraceEvent::MemoryMapSnapshot {
                event_id, regions, ..
            } => {
                model = Some(MemoryMapModel::from_canonical_regions(regions.clone())?);
                if *event_id >= target_event_id {
                    break;
                }
            }
            TraceEvent::MemoryMapRemove {
                event_id,
                source_event_id,
                region,
                ..
            } => {
                if *event_id <= target_event_id || *source_event_id <= target_event_id {
                    if let Some(m) = model.as_mut() {
                        m.apply_remove(region)?;
                    }
                }
            }
            TraceEvent::MemoryMapAdd {
                event_id,
                source_event_id,
                region,
                ..
            } => {
                if *event_id <= target_event_id || *source_event_id <= target_event_id {
                    if let Some(m) = model.as_mut() {
                        m.apply_add(region.clone())?;
                    }
                }
            }
            TraceEvent::SyscallEnter { event_id, .. }
            | TraceEvent::SyscallExit { event_id, .. }
            | TraceEvent::KernelMemoryWrite { event_id, .. }
            | TraceEvent::SignalDelivery { event_id, .. } => {
                if *event_id > target_event_id {
                    break;
                }
            }
        }
    }

    model.ok_or_else(|| "trace is missing initial MemoryMapSnapshot event".to_string())
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

/// Reads a trace file from disk and returns its validated event list (compatible with V1, V2, V3, and V4).
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
            TraceEvent::MemoryMapSnapshot {
                event_id,
                tid,
                regions,
            } => {
                println!(
                    "{:06} memory-map-snapshot tid={} regions={}",
                    event_id,
                    tid,
                    regions.len()
                );
            }
            TraceEvent::MemoryMapAdd {
                event_id,
                tid,
                source_event_id,
                region,
            } => {
                println!(
                    "{:06} memory-map-add    tid={} source={:06} {}",
                    event_id,
                    tid,
                    source_event_id,
                    region.format_maps_line()
                );
            }
            TraceEvent::MemoryMapRemove {
                event_id,
                tid,
                source_event_id,
                region,
            } => {
                println!(
                    "{:06} memory-map-remove tid={} source={:06} {}",
                    event_id,
                    tid,
                    source_event_id,
                    region.format_maps_line()
                );
            }
            TraceEvent::SignalDelivery {
                event_id,
                tid,
                signal_number,
                si_errno,
                si_code,
                siginfo_bytes,
            } => {
                println!(
                    "{:06} signal-delivery tid={} sig={} code={} errno={} siginfo_len={}",
                    event_id,
                    tid,
                    signal_number,
                    si_code,
                    si_errno,
                    siginfo_bytes.len()
                );
            }
        }
    }

    Ok(())
}
