use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,

    pub prot_read: bool,
    pub prot_write: bool,
    pub prot_exec: bool,

    pub shared: bool,

    pub file_offset: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,

    pub label: Vec<u8>,
}

impl MemoryRegion {
    pub const PAGE_SIZE: u64 = 4096;

    pub fn validate(&self) -> Result<(), String> {
        if self.start >= self.end {
            return Err(format!(
                "invalid region bounds: start 0x{:x} >= end 0x{:x}",
                self.start, self.end
            ));
        }
        if !self.start.is_multiple_of(Self::PAGE_SIZE) {
            return Err(format!(
                "region start 0x{:x} is not aligned to 4096-byte page boundary",
                self.start
            ));
        }
        if !self.end.is_multiple_of(Self::PAGE_SIZE) {
            return Err(format!(
                "region end 0x{:x} is not aligned to 4096-byte page boundary",
                self.end
            ));
        }
        Ok(())
    }

    pub fn canonical_eq(&self, other: &Self) -> bool {
        self.start == other.start
            && self.end == other.end
            && self.prot_read == other.prot_read
            && self.prot_write == other.prot_write
            && self.prot_exec == other.prot_exec
            && self.shared == other.shared
            && self.file_offset == other.file_offset
            && self.dev_major == other.dev_major
            && self.dev_minor == other.dev_minor
            && self.inode == other.inode
    }

    pub fn prot_bits(&self) -> u8 {
        (self.prot_read as u8) | ((self.prot_write as u8) << 1) | ((self.prot_exec as u8) << 2)
    }

    pub fn sharing_byte(&self) -> u8 {
        if self.shared {
            2
        } else {
            1
        }
    }

    pub fn format_maps_line(&self) -> String {
        let perms = format!(
            "{}{}{}{}",
            if self.prot_read { 'r' } else { '-' },
            if self.prot_write { 'w' } else { '-' },
            if self.prot_exec { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' }
        );
        let label_str = String::from_utf8_lossy(&self.label);
        if label_str.is_empty() {
            format!(
                "{:08x}-{:08x} {} {:08x} {:02x}:{:02x} {}",
                self.start,
                self.end,
                perms,
                self.file_offset,
                self.dev_major,
                self.dev_minor,
                self.inode
            )
        } else {
            format!(
                "{:08x}-{:08x} {} {:08x} {:02x}:{:02x} {} {}",
                self.start,
                self.end,
                perms,
                self.file_offset,
                self.dev_major,
                self.dev_minor,
                self.inode,
                label_str
            )
        }
    }
}

pub fn validate_regions_canonical_order(regions: &[MemoryRegion]) -> Result<(), String> {
    for region in regions {
        region.validate()?;
    }

    for i in 1..regions.len() {
        if regions[i - 1].start >= regions[i].start {
            return Err(format!(
                "non-canonical snapshot ordering: region start 0x{:x} is not strictly less than subsequent region start 0x{:x}",
                regions[i - 1].start,
                regions[i].start
            ));
        }
        if regions[i - 1].end > regions[i].start {
            return Err(format!(
                "overlapping regions detected: [0x{:x}, 0x{:x}) overlaps with [0x{:x}, 0x{:x})",
                regions[i - 1].start,
                regions[i - 1].end,
                regions[i].start,
                regions[i].end
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryMapModel {
    regions: Vec<MemoryRegion>,
}

impl MemoryMapModel {
    pub fn new(mut regions: Vec<MemoryRegion>) -> Result<Self, String> {
        regions.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));

        validate_regions_canonical_order(&regions)?;
        Ok(Self { regions })
    }

    pub fn from_canonical_regions(regions: Vec<MemoryRegion>) -> Result<Self, String> {
        validate_regions_canonical_order(&regions)?;
        Ok(Self { regions })
    }

    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    pub fn contains_address(&self, addr: u64) -> bool {
        self.region_containing(addr).is_some()
    }

    pub fn region_containing(&self, addr: u64) -> Option<&MemoryRegion> {
        match self.regions.binary_search_by(|r| {
            if addr < r.start {
                std::cmp::Ordering::Greater
            } else if addr >= r.end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(idx) => Some(&self.regions[idx]),
            Err(_) => None,
        }
    }

    pub fn apply_remove(&mut self, region: &MemoryRegion) -> Result<(), String> {
        if let Some(pos) = self.regions.iter().position(|r| r.canonical_eq(region)) {
            self.regions.remove(pos);
            Ok(())
        } else {
            Err(format!(
                "semantic error: attempt to remove non-existent memory region [0x{:x}, 0x{:x})",
                region.start, region.end
            ))
        }
    }

    pub fn apply_add(&mut self, region: MemoryRegion) -> Result<(), String> {
        region.validate()?;

        for existing in &self.regions {
            if region.start < existing.end && region.end > existing.start {
                return Err(format!(
                    "semantic error: attempt to add region [0x{:x}, 0x{:x}) which overlaps with existing [0x{:x}, 0x{:x})",
                    region.start, region.end, existing.start, existing.end
                ));
            }
        }

        let insert_pos = match self
            .regions
            .binary_search_by(|r| r.start.cmp(&region.start))
        {
            Ok(_) => {
                return Err(format!(
                    "semantic error: attempt to add region with duplicate start 0x{:x}",
                    region.start
                ));
            }
            Err(pos) => pos,
        };

        self.regions.insert(insert_pos, region);
        Ok(())
    }

    pub fn diff(&self, new_model: &MemoryMapModel) -> (Vec<MemoryRegion>, Vec<MemoryRegion>) {
        let mut removes = Vec::new();
        let mut adds = Vec::new();

        for old_region in &self.regions {
            if !new_model
                .regions
                .iter()
                .any(|nr| nr.canonical_eq(old_region))
            {
                removes.push(old_region.clone());
            }
        }

        for new_region in &new_model.regions {
            if !self.regions.iter().any(|or| or.canonical_eq(new_region)) {
                adds.push(new_region.clone());
            }
        }

        removes.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
        adds.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));

        (removes, adds)
    }
}

pub fn parse_proc_maps_bytes(maps_bytes: &[u8]) -> Result<MemoryMapModel, String> {
    let mut regions = Vec::new();

    for raw_line in maps_bytes.split(|&b| b == b'\n') {
        let line = if let Some(stripped) = raw_line.strip_suffix(b"\r") {
            stripped
        } else {
            raw_line
        };

        let mut idx = 0;
        while idx < line.len() && (line[idx] == b' ' || line[idx] == b'\t') {
            idx += 1;
        }
        if idx >= line.len() {
            continue;
        }

        let range_start = idx;
        while idx < line.len() && line[idx] != b' ' && line[idx] != b'\t' {
            idx += 1;
        }
        let range_bytes = &line[range_start..idx];
        let hyphen_pos = range_bytes
            .iter()
            .position(|&b| b == b'-')
            .ok_or_else(|| "invalid range format in proc maps line".to_string())?;

        let start_str = std::str::from_utf8(&range_bytes[..hyphen_pos])
            .map_err(|e| format!("invalid start hex in proc maps line: {}", e))?;
        let end_str = std::str::from_utf8(&range_bytes[hyphen_pos + 1..])
            .map_err(|e| format!("invalid end hex in proc maps line: {}", e))?;

        let start = u64::from_str_radix(start_str, 16)
            .map_err(|e| format!("invalid start hex '{}': {}", start_str, e))?;
        let end = u64::from_str_radix(end_str, 16)
            .map_err(|e| format!("invalid end hex '{}': {}", end_str, e))?;

        while idx < line.len() && (line[idx] == b' ' || line[idx] == b'\t') {
            idx += 1;
        }
        if idx >= line.len() {
            return Err("missing permissions field in proc maps line".to_string());
        }

        let perms_start = idx;
        while idx < line.len() && line[idx] != b' ' && line[idx] != b'\t' {
            idx += 1;
        }
        let perm_bytes = &line[perms_start..idx];
        if perm_bytes.len() != 4 {
            return Err(format!(
                "invalid permissions field length: expected 4 bytes, got {}",
                perm_bytes.len()
            ));
        }
        let prot_read = match perm_bytes[0] {
            b'r' => true,
            b'-' => false,
            c => return Err(format!("invalid read permission char '{}'", c as char)),
        };
        let prot_write = match perm_bytes[1] {
            b'w' => true,
            b'-' => false,
            c => return Err(format!("invalid write permission char '{}'", c as char)),
        };
        let prot_exec = match perm_bytes[2] {
            b'x' => true,
            b'-' => false,
            c => return Err(format!("invalid exec permission char '{}'", c as char)),
        };
        let shared = match perm_bytes[3] {
            b's' => true,
            b'p' => false,
            c => return Err(format!("invalid sharing char '{}'", c as char)),
        };

        while idx < line.len() && (line[idx] == b' ' || line[idx] == b'\t') {
            idx += 1;
        }
        if idx >= line.len() {
            return Err("missing file offset field in proc maps line".to_string());
        }

        let offset_start = idx;
        while idx < line.len() && line[idx] != b' ' && line[idx] != b'\t' {
            idx += 1;
        }
        let offset_bytes = &line[offset_start..idx];
        let offset_str = std::str::from_utf8(offset_bytes)
            .map_err(|e| format!("invalid offset hex in proc maps line: {}", e))?;
        let file_offset = u64::from_str_radix(offset_str, 16)
            .map_err(|e| format!("invalid offset hex '{}': {}", offset_str, e))?;

        while idx < line.len() && (line[idx] == b' ' || line[idx] == b'\t') {
            idx += 1;
        }
        if idx >= line.len() {
            return Err("missing device field in proc maps line".to_string());
        }

        let dev_start = idx;
        while idx < line.len() && line[idx] != b' ' && line[idx] != b'\t' {
            idx += 1;
        }
        let dev_bytes = &line[dev_start..idx];
        let colon_pos = dev_bytes
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| "invalid dev format in proc maps line".to_string())?;
        let major_str = std::str::from_utf8(&dev_bytes[..colon_pos])
            .map_err(|e| format!("invalid dev major hex: {}", e))?;
        let minor_str = std::str::from_utf8(&dev_bytes[colon_pos + 1..])
            .map_err(|e| format!("invalid dev minor hex: {}", e))?;
        let dev_major = u32::from_str_radix(major_str, 16)
            .map_err(|e| format!("invalid dev major hex '{}': {}", major_str, e))?;
        let dev_minor = u32::from_str_radix(minor_str, 16)
            .map_err(|e| format!("invalid dev minor hex '{}': {}", minor_str, e))?;

        while idx < line.len() && (line[idx] == b' ' || line[idx] == b'\t') {
            idx += 1;
        }
        if idx >= line.len() {
            return Err("missing inode field in proc maps line".to_string());
        }

        let inode_start = idx;
        while idx < line.len() && line[idx] != b' ' && line[idx] != b'\t' {
            idx += 1;
        }
        let inode_bytes = &line[inode_start..idx];
        let inode_str = std::str::from_utf8(inode_bytes)
            .map_err(|e| format!("invalid inode in proc maps line: {}", e))?;
        let inode = inode_str
            .parse::<u64>()
            .map_err(|e| format!("invalid inode '{}': {}", inode_str, e))?;

        while idx < line.len() && (line[idx] == b' ' || line[idx] == b'\t') {
            idx += 1;
        }
        let label = if idx < line.len() {
            line[idx..].to_vec()
        } else {
            Vec::new()
        };

        regions.push(MemoryRegion {
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
        });
    }

    MemoryMapModel::new(regions)
}

pub fn parse_proc_maps(maps_text: &str) -> Result<MemoryMapModel, String> {
    parse_proc_maps_bytes(maps_text.as_bytes())
}

pub fn read_process_maps(pid: libc::pid_t) -> Result<MemoryMapModel, String> {
    let proc_path = format!("/proc/{}/maps", pid);
    let bytes = fs::read(Path::new(&proc_path))
        .map_err(|e| format!("failed to read proc maps from {}: {}", proc_path, e))?;
    parse_proc_maps_bytes(&bytes)
}
