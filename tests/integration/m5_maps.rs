use causal::maps::{
    parse_proc_maps, parse_proc_maps_bytes, validate_regions_canonical_order, MemoryMapModel,
    MemoryRegion,
};
use causal::replay::run_replay;
use causal::trace::{
    parse_trace_bytes, read_trace_file_versioned, reconstruct_maps_at_event, TraceEvent,
    TraceWriter, SYS_BRK_X86_64, SYS_MMAP_X86_64, SYS_MPROTECT_X86_64, SYS_MUNMAP_X86_64,
    TRACE_VERSION_3,
};
use causal::tracer::{run_tracee, TraceeTermination};
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::PathBuf;
use std::process::Command;

fn get_fixture_path(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(manifest_dir).join("tests/bin").join(name);
    assert!(
        path.exists(),
        "fixture binary '{}' not found; run ./scripts/build-fixtures.sh first",
        path.display()
    );
    path
}

fn create_temp_trace_path(prefix: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "causal_test_{}_{}_{}.trace",
        prefix,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    dir
}

// ---------------------------------------------------------------------------
// 1. Unit Tests for MemoryRegion and MemoryMapModel
// ---------------------------------------------------------------------------

#[test]
fn test_m5_memory_region_validation_and_canonical_eq() {
    // Valid region
    let r1 = MemoryRegion {
        start: 0x7000_0000_0000,
        end: 0x7000_0001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: b"[heap]".to_vec(),
    };
    assert!(r1.validate().is_ok());

    // Canonical equality ignores label, whereas PartialEq compares all fields
    let mut r2 = r1.clone();
    r2.label = b"[anon]".to_vec();
    assert_ne!(r1, r2);
    assert!(r1.canonical_eq(&r2));

    // Unaligned start
    let mut r_invalid = r1.clone();
    r_invalid.start = 0x7000_0000_0001;
    assert!(r_invalid.validate().is_err());

    // start >= end
    let mut r_inverted = r1.clone();
    r_inverted.start = 0x7000_0002_0000;
    assert!(r_inverted.validate().is_err());
}

#[test]
fn test_m5_memory_map_model_mutations() {
    let r1 = MemoryRegion {
        start: 0x1000_0000,
        end: 0x1001_0000,
        prot_read: true,
        prot_write: false,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    let r2 = MemoryRegion {
        start: 0x2000_0000,
        end: 0x2001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };

    let mut model = MemoryMapModel::new(vec![r1.clone(), r2.clone()]).unwrap();
    assert_eq!(model.regions().len(), 2);
    assert!(model.contains_address(0x1000_5000));
    assert!(!model.contains_address(0x1500_0000));

    // Apply remove
    model.apply_remove(&r1).unwrap();
    assert_eq!(model.regions().len(), 1);
    assert!(!model.contains_address(0x1000_5000));

    // Apply add
    model.apply_add(r1.clone()).unwrap();
    assert_eq!(model.regions().len(), 2);
    assert_eq!(model.regions()[0], r1); // Sorted by start ascending

    // Adding overlapping region must fail
    let r_overlap = MemoryRegion {
        start: 0x1000_8000,
        end: 0x1002_0000,
        prot_read: true,
        prot_write: false,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    assert!(model.apply_add(r_overlap).is_err());
}

#[test]
fn test_m5_proc_maps_parser() {
    let maps_content = "\
55b8813e8000-55b8813e9000 r--p 00000000 08:01 12345                      /bin/cat
55b8813e9000-55b8813eb000 r-xp 00001000 08:01 12345                      /bin/cat
7ffc9d000000-7ffc9d021000 rw-p 00000000 00:00 0                          [stack]
7ffc9d0e7000-7ffc9d0eb000 r--p 00000000 00:00 0                          [vvar]
7ffc9d0eb000-7ffc9d0ed000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
";
    let model = parse_proc_maps(maps_content).unwrap();
    assert_eq!(model.regions().len(), 6);
    assert_eq!(model.regions()[0].start, 0x55b8813e8000);
    assert_eq!(model.regions()[0].end, 0x55b8813e9000);
    assert_eq!(model.regions()[0].label, b"/bin/cat");
    assert!(model.regions()[0].prot_read);
    assert!(!model.regions()[0].prot_write);
    assert!(!model.regions()[0].prot_exec);
    assert!(!model.regions()[0].shared);
}

#[test]
fn test_m5_proc_maps_label_extraction_and_non_utf8() {
    // 1. Inode = 0 with [stack] label
    let stack_line = b"7ffc9d000000-7ffc9d021000 rw-p 00000000 00:00 0 [stack]\n";
    let model_stack = parse_proc_maps_bytes(stack_line).unwrap();
    assert_eq!(model_stack.regions().len(), 1);
    assert_eq!(model_stack.regions()[0].inode, 0);
    assert_eq!(model_stack.regions()[0].label, b"[stack]");

    // 2. Label with spaces and special markers
    let spaces_line =
        b"55b8813e8000-55b8813e9000 r-xp 00000000 08:01 12345 /home/user/my app/bin (deleted)\n";
    let model_spaces = parse_proc_maps_bytes(spaces_line).unwrap();
    assert_eq!(model_spaces.regions().len(), 1);
    assert_eq!(
        model_spaces.regions()[0].label,
        b"/home/user/my app/bin (deleted)"
    );

    // 3. Label containing invalid UTF-8 bytes (Criterion V)
    let non_utf8_line = b"7fff00000000-7fff00010000 r-xp 00000000 08:01 12345 /tmp/\xff\xfe\xfd\n";
    let model_non_utf8 = parse_proc_maps_bytes(non_utf8_line).unwrap();
    assert_eq!(model_non_utf8.regions().len(), 1);
    let region = &model_non_utf8.regions()[0];
    assert_eq!(region.start, 0x7fff_0000_0000);
    assert_eq!(region.end, 0x7fff_0001_0000);
    assert_eq!(region.label, b"/tmp/\xff\xfe\xfd");
    assert!(region.prot_read);
    assert!(!region.prot_write);
    assert!(region.prot_exec);
    assert!(!region.shared);

    // Presentation format uses lossy UTF-8 conversion without panic
    let formatted = region.format_maps_line();
    assert!(formatted.contains("7fff00000000-7fff00010000"));
}

#[test]
fn test_m5_diff_apply_self_consistency() {
    // 1. Test mprotect split self-consistency (Criterion AJ)
    let old_r = MemoryRegion {
        start: 0x1000_0000,
        end: 0x1004_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    let old_model = MemoryMapModel::new(vec![old_r]).unwrap();

    let split_1 = MemoryRegion {
        start: 0x1000_0000,
        end: 0x1001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    let split_2 = MemoryRegion {
        start: 0x1001_0000,
        end: 0x1002_0000,
        prot_read: true,
        prot_write: false,
        prot_exec: true,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    let split_3 = MemoryRegion {
        start: 0x1002_0000,
        end: 0x1004_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    let mprotected_model = MemoryMapModel::new(vec![split_1, split_2, split_3]).unwrap();

    let (removes, adds) = old_model.diff(&mprotected_model);
    assert_eq!(removes.len(), 1);
    assert_eq!(adds.len(), 3);

    let mut check_model = old_model.clone();
    for r in &removes {
        check_model.apply_remove(r).unwrap();
    }
    for a in adds {
        check_model.apply_add(a).unwrap();
    }
    assert_eq!(check_model, mprotected_model);

    // 2. Test munmap hole self-consistency (Criterion AK)
    let hole_1 = MemoryRegion {
        start: 0x1000_0000,
        end: 0x1001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    let hole_2 = MemoryRegion {
        start: 0x1003_0000,
        end: 0x1004_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };
    let unmapped_model = MemoryMapModel::new(vec![hole_1, hole_2]).unwrap();

    let (removes_unmap, adds_unmap) = old_model.diff(&unmapped_model);
    let mut check_unmap = old_model;
    for r in &removes_unmap {
        check_unmap.apply_remove(r).unwrap();
    }
    for a in adds_unmap {
        check_unmap.apply_add(a).unwrap();
    }
    assert_eq!(check_unmap, unmapped_model);
}

// ---------------------------------------------------------------------------
// 2. Integration Tests: Recording and Memory Map Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_m5_initial_snapshot_evidence() {
    let fixture = get_fixture_path("map_model");
    let trace_path = create_temp_trace_path("snapshot_evidence");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_3);

    // Criteria G, H, I, J, X:
    // Event 1 must be MemoryMapSnapshot with non-empty regions, sorted, non-overlapping, preceding first SyscallEnter
    match &parsed.events[0] {
        TraceEvent::MemoryMapSnapshot {
            event_id, regions, ..
        } => {
            assert_eq!(*event_id, 1);
            assert!(!regions.is_empty(), "snapshot must contain initial regions");
            for i in 1..regions.len() {
                assert!(regions[i - 1].end <= regions[i].start);
            }

            // Must contain an executable region (e.g. text segment or ld.so)
            let has_exec = regions.iter().any(|r| r.prot_exec);
            assert!(has_exec, "snapshot must contain executable region");

            // Must contain [stack] when host exposes it
            let has_stack = regions.iter().any(|r| r.label == b"[stack]");
            assert!(has_stack, "snapshot must contain [stack] region");
        }
        other => panic!("expected event 1 to be MemoryMapSnapshot, got {:?}", other),
    }

    // First SyscallEnter must have event_id > 1
    let first_enter = parsed
        .events
        .iter()
        .find(|e| matches!(e, TraceEvent::SyscallEnter { .. }))
        .unwrap();
    assert!(
        first_enter.event_id() > 1,
        "first SyscallEnter must follow MemoryMapSnapshot"
    );

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_recording_map_model_fixture_lifecycle() {
    let fixture = get_fixture_path("map_model");
    let trace_path = create_temp_trace_path("map_model");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_3);

    // Event 1 must be MemoryMapSnapshot
    match &parsed.events[0] {
        TraceEvent::MemoryMapSnapshot {
            event_id, regions, ..
        } => {
            assert_eq!(*event_id, 1);
            assert!(!regions.is_empty(), "snapshot must contain initial regions");
            for i in 1..regions.len() {
                assert!(regions[i - 1].end <= regions[i].start);
            }
        }
        other => panic!("expected event 1 to be MemoryMapSnapshot, got {:?}", other),
    }

    // Verify deltas exist for mmap, mprotect, and munmap
    let mut mmap_exits = Vec::new();
    let mut mprotect_exits = Vec::new();
    let mut munmap_exits = Vec::new();
    let mut map_adds = Vec::new();
    let mut map_removes = Vec::new();

    for ev in &parsed.events {
        match ev {
            TraceEvent::SyscallExit {
                event_id,
                number,
                result,
                ..
            } => {
                if *number == SYS_MMAP_X86_64 && *result > 0 {
                    mmap_exits.push(*event_id);
                } else if *number == SYS_MPROTECT_X86_64 && *result == 0 {
                    mprotect_exits.push(*event_id);
                } else if *number == SYS_MUNMAP_X86_64 && *result == 0 {
                    munmap_exits.push(*event_id);
                }
            }
            TraceEvent::MemoryMapAdd {
                event_id,
                source_event_id,
                region,
                ..
            } => {
                map_adds.push((*event_id, *source_event_id, region.clone()));
            }
            TraceEvent::MemoryMapRemove {
                event_id,
                source_event_id,
                region,
                ..
            } => {
                map_removes.push((*event_id, *source_event_id, region.clone()));
            }
            _ => {}
        }
    }

    assert!(!mmap_exits.is_empty(), "must observe mmap exit");
    assert!(!mprotect_exits.is_empty(), "must observe mprotect exit");
    assert!(!munmap_exits.is_empty(), "must observe munmap exit");

    // Check that mmap produced MemoryMapAdd sourced to mmap exit
    let mmap_adds: Vec<_> = map_adds
        .iter()
        .filter(|(_, src, _)| *src == mmap_exits[0])
        .collect();
    assert_eq!(mmap_adds.len(), 1, "mmap must produce exactly 1 add delta");

    // Check that mprotect produced MemoryMapRemove followed by MemoryMapAdds
    let mprotect_removes: Vec<_> = map_removes
        .iter()
        .filter(|(_, src, _)| *src == mprotect_exits[0])
        .collect();
    let mprotect_adds: Vec<_> = map_adds
        .iter()
        .filter(|(_, src, _)| *src == mprotect_exits[0])
        .collect();
    assert!(
        !mprotect_removes.is_empty(),
        "mprotect must produce remove delta"
    );
    assert!(
        !mprotect_adds.is_empty(),
        "mprotect must produce add deltas"
    );

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_recording_brk_model_fixture() {
    let fixture = get_fixture_path("brk_model");
    let trace_path = create_temp_trace_path("brk_model");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_3);

    // Verify brk exits have matching deltas
    let brk_deltas_count = parsed
        .events
        .iter()
        .filter(|e| {
            matches!(
                e,
                TraceEvent::MemoryMapAdd { .. } | TraceEvent::MemoryMapRemove { .. }
            )
        })
        .count();

    assert!(
        brk_deltas_count > 0,
        "brk growth/shrink must generate map deltas"
    );

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_recording_map_fail_produces_no_deltas() {
    let fixture = get_fixture_path("map_fail");
    let trace_path = create_temp_trace_path("map_fail");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_3);

    // Filter failed mapping exits
    let failed_exits: Vec<u64> = parsed
        .events
        .iter()
        .filter_map(|e| match e {
            TraceEvent::SyscallExit {
                event_id,
                number,
                result,
                ..
            } if (*number == SYS_MMAP_X86_64
                || *number == SYS_MPROTECT_X86_64
                || *number == SYS_MUNMAP_X86_64)
                && *result < 0 =>
            {
                Some(*event_id)
            }
            _ => None,
        })
        .collect();

    assert!(
        !failed_exits.is_empty(),
        "must observe at least one failed mapping syscall"
    );

    // Verify NO deltas are sourced to any failed exit
    for ev in &parsed.events {
        match ev {
            TraceEvent::MemoryMapAdd {
                event_id,
                source_event_id,
                ..
            }
            | TraceEvent::MemoryMapRemove {
                event_id,
                source_event_id,
                ..
            } => {
                assert!(
                    !failed_exits.contains(source_event_id),
                    "delta event {} was improperly sourced to failed exit event {}",
                    event_id,
                    source_event_id
                );
            }
            _ => {}
        }
    }

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_failed_mapping_historical_invariance() {
    let fixture = get_fixture_path("map_fail");
    let trace_path = create_temp_trace_path("map_fail_invariance");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();

    let failed_exits: Vec<u64> = parsed
        .events
        .iter()
        .filter_map(|e| match e {
            TraceEvent::SyscallExit {
                event_id,
                number,
                result,
                ..
            } if (*number == SYS_MMAP_X86_64
                || *number == SYS_MPROTECT_X86_64
                || *number == SYS_MUNMAP_X86_64)
                && *result < 0 =>
            {
                Some(*event_id)
            }
            _ => None,
        })
        .collect();

    assert!(!failed_exits.is_empty());

    // Criterion AP: Reconstructed model before failed exit == model after failed exit
    for exit_id in failed_exits {
        let model_before = reconstruct_maps_at_event(&parsed, exit_id - 1).unwrap();
        let model_after = reconstruct_maps_at_event(&parsed, exit_id).unwrap();
        assert_eq!(
            model_before, model_after,
            "failed mapping exit {} must not alter reconstructed map model",
            exit_id
        );
    }

    let _ = fs::remove_file(&trace_path);
}

// ---------------------------------------------------------------------------
// 3. Historical Map Query (`reconstruct_maps_at_event` & CLI)
// ---------------------------------------------------------------------------

#[test]
fn test_m5_reconstruct_maps_historical_query() {
    let fixture = get_fixture_path("map_model");
    let trace_path = create_temp_trace_path("maps_query");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();

    // Query at snapshot event 1
    let model_at_1 = reconstruct_maps_at_event(&parsed, 1).unwrap();
    assert!(!model_at_1.regions().is_empty());

    // Find mmap exit in target code (64KB allocation)
    let mut mmap_addr = 0;
    let mut mmap_exit_id = 0;
    for (i, ev) in parsed.events.iter().enumerate() {
        if let TraceEvent::SyscallEnter { number, args, .. } = ev {
            if *number == SYS_MMAP_X86_64 && args[1] == 65536 {
                for next_ev in &parsed.events[i + 1..] {
                    if let TraceEvent::SyscallExit {
                        number,
                        result,
                        event_id,
                        ..
                    } = next_ev
                    {
                        if *number == SYS_MMAP_X86_64 && *result > 0 {
                            mmap_addr = *result as u64;
                            mmap_exit_id = *event_id;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    assert!(mmap_addr > 0);

    // Reconstruct maps before and after mmap
    let model_before = reconstruct_maps_at_event(&parsed, mmap_exit_id - 1).unwrap();
    let model_after = reconstruct_maps_at_event(&parsed, mmap_exit_id).unwrap();

    assert!(!model_before.contains_address(mmap_addr));
    assert!(model_after.contains_address(mmap_addr));

    // Criterion AM: Query mprotect exit (protect middle 16KB to RX)
    let mut mprotect_exit_id = 0;
    for (i, ev) in parsed.events.iter().enumerate() {
        if let TraceEvent::SyscallEnter { number, args, .. } = ev {
            if *number == SYS_MPROTECT_X86_64 && args[0] == mmap_addr + 16384 {
                for next_ev in &parsed.events[i + 1..] {
                    if let TraceEvent::SyscallExit {
                        number, event_id, ..
                    } = next_ev
                    {
                        if *number == SYS_MPROTECT_X86_64 {
                            mprotect_exit_id = *event_id;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    assert!(mprotect_exit_id > 0);

    let model_mprotect = reconstruct_maps_at_event(&parsed, mprotect_exit_id).unwrap();
    // Subrange ptr+16KB..ptr+32KB should have RX permissions
    let prot_region = model_mprotect
        .region_containing(mmap_addr + 16384)
        .expect("mprotect subrange must be present in model");
    assert!(prot_region.prot_read);
    assert!(!prot_region.prot_write);
    assert!(prot_region.prot_exec);

    // Outside subranges remain mapped
    let low_region = model_mprotect
        .region_containing(mmap_addr)
        .expect("low subrange must remain mapped");
    assert!(low_region.prot_read);
    assert!(low_region.prot_write);
    assert!(!low_region.prot_exec);

    // Criterion AN: Query munmap exit (unmaps ptr+32KB..ptr+48KB)
    let mut munmap_exit_id = 0;
    for (i, ev) in parsed.events.iter().enumerate() {
        if let TraceEvent::SyscallEnter { number, args, .. } = ev {
            if *number == SYS_MUNMAP_X86_64 && args[0] == mmap_addr + 32768 {
                for next_ev in &parsed.events[i + 1..] {
                    if let TraceEvent::SyscallExit {
                        number, event_id, ..
                    } = next_ev
                    {
                        if *number == SYS_MUNMAP_X86_64 {
                            munmap_exit_id = *event_id;
                            break;
                        }
                    }
                }
                break;
            }
        }
    }
    assert!(munmap_exit_id > 0);

    let model_munmap = reconstruct_maps_at_event(&parsed, munmap_exit_id).unwrap();
    // Unmapped target address is absent
    assert!(
        !model_munmap.contains_address(mmap_addr + 32768 + 100),
        "unmapped subrange must be absent from model"
    );
    // Remaining portions stay mapped
    assert!(
        model_munmap.contains_address(mmap_addr + 100),
        "lower subrange must stay mapped"
    );
    assert!(
        model_munmap.contains_address(mmap_addr + 49152 + 100),
        "upper subrange must stay mapped"
    );

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_reconstruct_maps_brk_historical_query() {
    // Criterion AO: Historical query for brk growth and shrinkage
    let fixture = get_fixture_path("brk_model");
    let trace_path = create_temp_trace_path("brk_query");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();

    // Find brk exits
    let brk_exits: Vec<(u64, i64)> = parsed
        .events
        .iter()
        .filter_map(|e| match e {
            TraceEvent::SyscallExit {
                event_id,
                number,
                result,
                ..
            } if *number == SYS_BRK_X86_64 => Some((*event_id, *result)),
            _ => None,
        })
        .collect();

    let len = brk_exits.len();
    assert!(len >= 3, "brk_model has 3 brk invocations in main");
    let initial_brk = brk_exits[len - 3].1 as u64;
    let growth_exit_id = brk_exits[len - 2].0;
    let shrink_exit_id = brk_exits[len - 1].0;

    // After growth: address initial_brk + 32KB is covered
    let model_growth = reconstruct_maps_at_event(&parsed, growth_exit_id).unwrap();
    assert!(
        model_growth.contains_address(initial_brk + 32768),
        "growth exit must cover expanded heap address"
    );

    // After shrink: address initial_brk + 32KB is no longer covered
    let model_shrink = reconstruct_maps_at_event(&parsed, shrink_exit_id).unwrap();
    assert!(
        !model_shrink.contains_address(initial_brk + 32768),
        "shrink exit must no longer cover shrunk heap address"
    );

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_causal_maps_cli() {
    let fixture = get_fixture_path("map_model");
    let trace_path = create_temp_trace_path("cli_maps");

    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let exe = env!("CARGO_BIN_EXE_causal");

    // Successful query
    let output = Command::new(exe)
        .args(["maps", trace_path.to_str().unwrap(), "1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("r-xp") || stdout.contains("r--p"));

    // Query on non-numeric event-id
    let output_invalid = Command::new(exe)
        .args(["maps", trace_path.to_str().unwrap(), "abc"])
        .output()
        .unwrap();
    assert_eq!(output_invalid.status.code(), Some(1));

    // Query on zero event-id
    let output_zero = Command::new(exe)
        .args(["maps", trace_path.to_str().unwrap(), "0"])
        .output()
        .unwrap();
    assert_eq!(output_zero.status.code(), Some(1));

    // Query on out-of-range event-id
    let output_oor = Command::new(exe)
        .args(["maps", trace_path.to_str().unwrap(), "999999"])
        .output()
        .unwrap();
    assert_eq!(output_oor.status.code(), Some(1));

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_causal_maps_rejection_of_v1_and_v2_traces() {
    let trace_path_v1 = create_temp_trace_path("reject_v1");
    let trace_path_v2 = create_temp_trace_path("reject_v2");

    // Write synthetic V1 trace
    {
        let file = File::create(&trace_path_v1).unwrap();
        let mut writer = TraceWriter::new_v1(BufWriter::new(file)).unwrap();
        writer.write_syscall_enter(100, 39, [0; 6]).unwrap();
        writer.write_syscall_exit(100, 39, 100).unwrap();
        writer.finish().unwrap();
    }

    // Write synthetic V2 trace
    {
        let file = File::create(&trace_path_v2).unwrap();
        let mut writer = TraceWriter::new_v2(BufWriter::new(file)).unwrap();
        writer.write_syscall_enter(100, 39, [0; 6]).unwrap();
        writer.write_syscall_exit(100, 39, 100).unwrap();
        writer.finish().unwrap();
    }

    let exe = env!("CARGO_BIN_EXE_causal");

    let out_v1 = Command::new(exe)
        .args(["maps", trace_path_v1.to_str().unwrap(), "1"])
        .output()
        .unwrap();
    assert_eq!(out_v1.status.code(), Some(1));
    let stderr_v1 = String::from_utf8_lossy(&out_v1.stderr);
    assert_eq!(
        stderr_v1.trim(),
        "causal: trace format V1 has no initial memory-map model; record again with V3"
    );

    let out_v2 = Command::new(exe)
        .args(["maps", trace_path_v2.to_str().unwrap(), "1"])
        .output()
        .unwrap();
    assert_eq!(out_v2.status.code(), Some(1));
    let stderr_v2 = String::from_utf8_lossy(&out_v2.stderr);
    assert_eq!(
        stderr_v2.trim(),
        "causal: trace format V2 has no initial memory-map model; record again with V3"
    );

    let _ = fs::remove_file(&trace_path_v1);
    let _ = fs::remove_file(&trace_path_v2);
}

// ---------------------------------------------------------------------------
// 4. Synthetic Serialization and Trace Validation
// ---------------------------------------------------------------------------

#[test]
fn test_m5_synthetic_v3_wire_roundtrip() {
    let mut buf = Vec::new();
    let region = MemoryRegion {
        start: 0x7fff_0000_0000,
        end: 0x7fff_0001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0x1000,
        dev_major: 8,
        dev_minor: 1,
        inode: 12345,
        label: b"/usr/lib/libc.so".to_vec(),
    };

    let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
    writer
        .write_memory_map_snapshot(50, std::slice::from_ref(&region))
        .unwrap();
    writer.write_syscall_enter(50, 9, [0; 6]).unwrap();
    let exit_id = writer.write_syscall_exit(50, 9, 0x7fff_0000_0000).unwrap();
    writer
        .write_memory_map_remove(50, exit_id, &region)
        .unwrap();
    writer.write_memory_map_add(50, exit_id, &region).unwrap();
    writer.finish().unwrap();

    let parsed = parse_trace_bytes(&buf).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_3);
    assert_eq!(parsed.events.len(), 5);
}

#[test]
fn test_m5_synthetic_v3_deterministic_serialization() {
    // Criterion BH: Exact binary byte reproducibility
    let region = MemoryRegion {
        start: 0x7fff_0000_0000,
        end: 0x7fff_0001_0000,
        prot_read: true,
        prot_write: true,
        prot_exec: false,
        shared: false,
        file_offset: 0x1000,
        dev_major: 8,
        dev_minor: 1,
        inode: 12345,
        label: b"/usr/lib/libc.so".to_vec(),
    };

    let mut buf_a = Vec::new();
    {
        let mut writer = TraceWriter::new_v3(&mut buf_a).unwrap();
        writer
            .write_memory_map_snapshot(50, std::slice::from_ref(&region))
            .unwrap();
        writer.write_syscall_enter(50, 9, [0; 6]).unwrap();
        let exit_id = writer.write_syscall_exit(50, 9, 0x7fff_0000_0000).unwrap();
        writer
            .write_memory_map_remove(50, exit_id, &region)
            .unwrap();
        writer.write_memory_map_add(50, exit_id, &region).unwrap();
        writer.finish().unwrap();
    }

    let mut buf_b = Vec::new();
    {
        let mut writer = TraceWriter::new_v3(&mut buf_b).unwrap();
        writer
            .write_memory_map_snapshot(50, std::slice::from_ref(&region))
            .unwrap();
        writer.write_syscall_enter(50, 9, [0; 6]).unwrap();
        let exit_id = writer.write_syscall_exit(50, 9, 0x7fff_0000_0000).unwrap();
        writer
            .write_memory_map_remove(50, exit_id, &region)
            .unwrap();
        writer.write_memory_map_add(50, exit_id, &region).unwrap();
        writer.finish().unwrap();
    }

    assert_eq!(
        buf_a, buf_b,
        "V3 serialization must be bit-for-bit deterministic"
    );
}

#[allow(clippy::too_many_arguments)]
fn encode_test_region_raw(
    start: u64,
    end: u64,
    offset: u64,
    inode: u64,
    major: u32,
    minor: u32,
    prot: u8,
    sharing: u8,
    reserved: [u8; 2],
    label: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&start.to_le_bytes());
    buf.extend_from_slice(&end.to_le_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&inode.to_le_bytes());
    buf.extend_from_slice(&major.to_le_bytes());
    buf.extend_from_slice(&minor.to_le_bytes());
    buf.push(prot);
    buf.push(sharing);
    buf.extend_from_slice(&reserved);
    buf.extend_from_slice(&(label.len() as u32).to_le_bytes());
    buf.extend_from_slice(label);
    buf
}

fn create_v3_header() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"CAUSAL\0\0");
    buf.extend_from_slice(&3_u32.to_le_bytes());
    buf.extend_from_slice(&1_u16.to_le_bytes()); // arch x86-64
    buf.push(1); // little endian (offset 14)
    buf.push(8); // pointer width 8 (offset 15)
    buf
}

fn create_v3_footer(event_count: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&event_count.to_le_bytes());
    buf.extend_from_slice(b"CAUSEND\0");
    buf
}

#[test]
fn test_m5_trace_validation_unsorted_snapshot_rejected() {
    // Criterion BO: Wire snapshot descriptors in non-canonical unsorted order must be rejected
    let mut buf = create_v3_header();
    let reg_b = encode_test_region_raw(0x3000_0000, 0x4000_0000, 0, 0, 0, 0, 1, 1, [0, 0], b"");
    let reg_a = encode_test_region_raw(0x1000_0000, 0x2000_0000, 0, 0, 0, 0, 1, 1, [0, 0], b"");

    let mut snap_body = Vec::new();
    snap_body.extend_from_slice(&1_u64.to_le_bytes()); // event_id
    snap_body.extend_from_slice(&10_u32.to_le_bytes()); // tid
    snap_body.extend_from_slice(&2_u32.to_le_bytes()); // region_count = 2
    snap_body.extend_from_slice(&0_u32.to_le_bytes()); // reserved = 0
    snap_body.extend_from_slice(&reg_b); // B first (0x3000_0000)
    snap_body.extend_from_slice(&reg_a); // A second (0x1000_0000) -> unsorted!

    let rec_len = 4 + snap_body.len();
    buf.extend_from_slice(&(rec_len as u32).to_le_bytes());
    buf.push(4); // kind = 4 (MemoryMapSnapshot)
    buf.extend_from_slice(&[0; 3]);
    buf.extend_from_slice(&snap_body);
    buf.extend_from_slice(&create_v3_footer(1));

    let res = parse_trace_bytes(&buf);
    assert!(res.is_err(), "unsorted wire snapshot must be rejected");
    let err = res.unwrap_err();
    assert!(
        err.contains("non-canonical snapshot ordering"),
        "error '{}' must indicate non-canonical snapshot ordering",
        err
    );
}

#[test]
fn test_m5_trace_validation_corruption_cases() {
    // Criteria BJ through BU: Focused rejection of synthetic corruption cases
    let valid_region = MemoryRegion {
        start: 0x1000_0000,
        end: 0x1001_0000,
        prot_read: true,
        prot_write: false,
        prot_exec: false,
        shared: false,
        file_offset: 0,
        dev_major: 0,
        dev_minor: 0,
        inode: 0,
        label: Vec::new(),
    };

    // Case 1: V3 missing initial snapshot before SyscallEnter (Criterion BJ)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer.write_syscall_enter(10, 39, [0; 6]).unwrap();
        writer.write_syscall_exit(10, 39, 10).unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 2: Duplicate initial snapshot (Criterion BK)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 3: Late snapshot (Snapshot after SyscallEnter)
    {
        let mut buf = create_v3_header();
        let mut enter_body = Vec::new();
        enter_body.extend_from_slice(&1_u64.to_le_bytes());
        enter_body.extend_from_slice(&10_u32.to_le_bytes());
        enter_body.extend_from_slice(&39_u64.to_le_bytes()); // SYS_getpid
        enter_body.extend_from_slice(&[0_u8; 48]);
        let rec_len1 = 4 + enter_body.len();
        buf.extend_from_slice(&(rec_len1 as u32).to_le_bytes());
        buf.push(1); // SyscallEnter
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&enter_body);

        let reg = encode_test_region_raw(0x1000_0000, 0x2000_0000, 0, 0, 0, 0, 1, 1, [0, 0], b"");
        let mut snap_body = Vec::new();
        snap_body.extend_from_slice(&2_u64.to_le_bytes());
        snap_body.extend_from_slice(&10_u32.to_le_bytes());
        snap_body.extend_from_slice(&1_u32.to_le_bytes());
        snap_body.extend_from_slice(&0_u32.to_le_bytes());
        snap_body.extend_from_slice(&reg);
        let rec_len2 = 4 + snap_body.len();
        buf.extend_from_slice(&(rec_len2 as u32).to_le_bytes());
        buf.push(4); // MemoryMapSnapshot
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&snap_body);
        buf.extend_from_slice(&create_v3_footer(2));
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 4: Invalid prot_bits > 7
    {
        let mut buf = create_v3_header();
        let reg_invalid_prot =
            encode_test_region_raw(0x1000_0000, 0x2000_0000, 0, 0, 0, 0, 8, 1, [0, 0], b"");
        let mut snap_body = Vec::new();
        snap_body.extend_from_slice(&1_u64.to_le_bytes());
        snap_body.extend_from_slice(&10_u32.to_le_bytes());
        snap_body.extend_from_slice(&1_u32.to_le_bytes());
        snap_body.extend_from_slice(&0_u32.to_le_bytes());
        snap_body.extend_from_slice(&reg_invalid_prot);
        let rec_len = 4 + snap_body.len();
        buf.extend_from_slice(&(rec_len as u32).to_le_bytes());
        buf.push(4);
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&snap_body);
        buf.extend_from_slice(&create_v3_footer(1));
        let res = parse_trace_bytes(&buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("invalid prot bits"));
    }

    // Case 5: Invalid sharing byte
    {
        let mut buf = create_v3_header();
        let reg_invalid_sharing =
            encode_test_region_raw(0x1000_0000, 0x2000_0000, 0, 0, 0, 0, 1, 3, [0, 0], b"");
        let mut snap_body = Vec::new();
        snap_body.extend_from_slice(&1_u64.to_le_bytes());
        snap_body.extend_from_slice(&10_u32.to_le_bytes());
        snap_body.extend_from_slice(&1_u32.to_le_bytes());
        snap_body.extend_from_slice(&0_u32.to_le_bytes());
        snap_body.extend_from_slice(&reg_invalid_sharing);
        let rec_len = 4 + snap_body.len();
        buf.extend_from_slice(&(rec_len as u32).to_le_bytes());
        buf.push(4);
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&snap_body);
        buf.extend_from_slice(&create_v3_footer(1));
        let res = parse_trace_bytes(&buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("invalid sharing byte"));
    }

    // Case 6: Nonzero descriptor reserved bytes
    {
        let mut buf = create_v3_header();
        let reg_nonzero_res =
            encode_test_region_raw(0x1000_0000, 0x2000_0000, 0, 0, 0, 0, 1, 1, [1, 0], b"");
        let mut snap_body = Vec::new();
        snap_body.extend_from_slice(&1_u64.to_le_bytes());
        snap_body.extend_from_slice(&10_u32.to_le_bytes());
        snap_body.extend_from_slice(&1_u32.to_le_bytes());
        snap_body.extend_from_slice(&0_u32.to_le_bytes());
        snap_body.extend_from_slice(&reg_nonzero_res);
        let rec_len = 4 + snap_body.len();
        buf.extend_from_slice(&(rec_len as u32).to_le_bytes());
        buf.push(4);
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&snap_body);
        buf.extend_from_slice(&create_v3_footer(1));
        let res = parse_trace_bytes(&buf);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("nonzero descriptor reserved bytes"));
    }

    // Case 7: label_len extending beyond record boundary
    {
        let mut buf = create_v3_header();
        let mut reg_bad_label =
            encode_test_region_raw(0x1000_0000, 0x2000_0000, 0, 0, 0, 0, 1, 1, [0, 0], b"test");
        reg_bad_label[44..48].copy_from_slice(&999_u32.to_le_bytes());
        let mut snap_body = Vec::new();
        snap_body.extend_from_slice(&1_u64.to_le_bytes());
        snap_body.extend_from_slice(&10_u32.to_le_bytes());
        snap_body.extend_from_slice(&1_u32.to_le_bytes());
        snap_body.extend_from_slice(&0_u32.to_le_bytes());
        snap_body.extend_from_slice(&reg_bad_label);
        let rec_len = 4 + snap_body.len();
        buf.extend_from_slice(&(rec_len as u32).to_le_bytes());
        buf.push(4);
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&snap_body);
        buf.extend_from_slice(&create_v3_footer(1));
        let res = parse_trace_bytes(&buf);
        assert!(res.is_err());
    }

    // Case 8: Snapshot region_count inconsistent with encoded data
    {
        let mut buf = create_v3_header();
        let reg = encode_test_region_raw(0x1000_0000, 0x2000_0000, 0, 0, 0, 0, 1, 1, [0, 0], b"");
        let mut snap_body = Vec::new();
        snap_body.extend_from_slice(&1_u64.to_le_bytes());
        snap_body.extend_from_slice(&10_u32.to_le_bytes());
        snap_body.extend_from_slice(&2_u32.to_le_bytes()); // claims 2 regions, 1 provided
        snap_body.extend_from_slice(&0_u32.to_le_bytes());
        snap_body.extend_from_slice(&reg);
        let rec_len = 4 + snap_body.len();
        buf.extend_from_slice(&(rec_len as u32).to_le_bytes());
        buf.push(4);
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&snap_body);
        buf.extend_from_slice(&create_v3_footer(1));
        let res = parse_trace_bytes(&buf);
        assert!(res.is_err());
    }

    // Case 9: Unknown V3 event kind
    {
        let mut buf = create_v3_header();
        let mut dummy_body = Vec::new();
        dummy_body.extend_from_slice(&1_u64.to_le_bytes()); // event_id = 1
        dummy_body.extend_from_slice(&10_u32.to_le_bytes()); // tid = 10
        let rec_len = 4 + dummy_body.len();
        buf.extend_from_slice(&(rec_len as u32).to_le_bytes());
        buf.push(99); // unknown event kind 99
        buf.extend_from_slice(&[0; 3]);
        buf.extend_from_slice(&dummy_body);
        buf.extend_from_slice(&create_v3_footer(1));
        let res = parse_trace_bytes(&buf);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("unknown event kind 99"));
    }

    // Case 10: Delta referencing non-mapping syscall (e.g. SYS_getpid 39) (Criterion BL)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer.write_syscall_enter(10, 39, [0; 6]).unwrap();
        let exit_id = writer.write_syscall_exit(10, 39, 10).unwrap();
        writer
            .write_memory_map_add(10, exit_id, &valid_region)
            .unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 11: Delta ordering violation (Add before Remove for same source exit) (Criterion BM)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer.write_syscall_enter(10, 9, [0; 6]).unwrap();
        let exit_id = writer.write_syscall_exit(10, 9, 0x1000_0000).unwrap();
        let new_region = MemoryRegion {
            start: 0x2000_0000,
            end: 0x2001_0000,
            prot_read: true,
            prot_write: true,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        writer
            .write_memory_map_add(10, exit_id, &new_region)
            .unwrap();
        writer
            .write_memory_map_remove(10, exit_id, &valid_region)
            .unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 12: Delta referencing non-existent source_event_id (Criterion BN)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer.write_syscall_enter(10, 9, [0; 6]).unwrap();
        writer.write_syscall_exit(10, 9, 0x1000_0000).unwrap();
        writer
            .write_memory_map_remove(10, 9999, &valid_region)
            .unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 13: MemoryMapRemove for region not in current model (Criterion BO)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer.write_syscall_enter(10, 9, [0; 6]).unwrap();
        let exit_id = writer.write_syscall_exit(10, 9, 0x1000_0000).unwrap();
        let non_existent_region = MemoryRegion {
            start: 0x9000_0000,
            end: 0x9001_0000,
            prot_read: true,
            prot_write: false,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        writer
            .write_memory_map_remove(10, exit_id, &non_existent_region)
            .unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 14: MemoryMapAdd for overlapping region (Criterion BP)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer.write_syscall_enter(10, 9, [0; 6]).unwrap();
        let exit_id = writer.write_syscall_exit(10, 9, 0x1000_0000).unwrap();
        let overlapping_region = MemoryRegion {
            start: 0x1000_8000,
            end: 0x1002_0000,
            prot_read: true,
            prot_write: true,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        writer
            .write_memory_map_add(10, exit_id, &overlapping_region)
            .unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 15: Delta not contiguous with source exit (Criterion BQ)
    {
        let mut buf = Vec::new();
        let mut writer = TraceWriter::new_v3(&mut buf).unwrap();
        writer
            .write_memory_map_snapshot(10, std::slice::from_ref(&valid_region))
            .unwrap();
        writer.write_syscall_enter(10, 9, [0; 6]).unwrap();
        let exit_id1 = writer.write_syscall_exit(10, 9, 0x1000_0000).unwrap();
        // Another syscall in between
        writer.write_syscall_enter(10, 39, [0; 6]).unwrap();
        writer.write_syscall_exit(10, 39, 10).unwrap();
        // Belated delta for first exit
        let new_region = MemoryRegion {
            start: 0x2000_0000,
            end: 0x2001_0000,
            prot_read: true,
            prot_write: true,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        writer
            .write_memory_map_add(10, exit_id1, &new_region)
            .unwrap();
        writer.finish().unwrap();
        assert!(parse_trace_bytes(&buf).is_err());
    }

    // Case 16: Descriptor bounds start >= end (Criterion BR)
    {
        let invalid_bounds = MemoryRegion {
            start: 0x2000_0000,
            end: 0x1000_0000,
            prot_read: true,
            prot_write: false,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        assert!(invalid_bounds.validate().is_err());
    }

    // Case 17: Descriptor unaligned start / end (Criterion BS)
    {
        let unaligned_start = MemoryRegion {
            start: 0x1000_0001,
            end: 0x1001_0000,
            prot_read: true,
            prot_write: false,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        assert!(unaligned_start.validate().is_err());

        let unaligned_end = MemoryRegion {
            start: 0x1000_0000,
            end: 0x1001_0001,
            prot_read: true,
            prot_write: false,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        assert!(unaligned_end.validate().is_err());
    }

    // Case 18: Snapshot overlapping regions (Criterion BT)
    {
        let r_a = MemoryRegion {
            start: 0x1000_0000,
            end: 0x1002_0000,
            prot_read: true,
            prot_write: false,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        let r_b = MemoryRegion {
            start: 0x1001_0000,
            end: 0x1003_0000,
            prot_read: true,
            prot_write: false,
            prot_exec: false,
            shared: false,
            file_offset: 0,
            dev_major: 0,
            dev_minor: 0,
            inode: 0,
            label: Vec::new(),
        };
        assert!(validate_regions_canonical_order(&[r_a, r_b]).is_err());
    }
}

// ---------------------------------------------------------------------------
// 5. Replay Compatibility with V3 Traces
// ---------------------------------------------------------------------------

#[test]
fn test_m5_replay_with_v3_trace_succeeds() {
    let fixture = get_fixture_path("getpid_replay");
    let trace_path = create_temp_trace_path("v3_replay");

    // Record V3 trace (default)
    let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
    assert_eq!(res, Ok(TraceeTermination::Exited(0)));

    let parsed = read_trace_file_versioned(&trace_path).unwrap();
    assert_eq!(parsed.version, TRACE_VERSION_3);

    // Replay against recorded V3 trace (replay skips map metadata)
    let replay_res = run_replay(&trace_path, fixture.to_str().unwrap(), &[]);
    assert_eq!(replay_res, Ok(TraceeTermination::Exited(0)));

    let _ = fs::remove_file(&trace_path);
}

#[test]
fn test_m5_v3_replay_read_and_mixed() {
    // Criteria AZ, BA, CC: V3 trace compatibility with M4 read substitution and mixed replay

    // 1. Read replay under V3 trace
    let fixture_read = get_fixture_path("read_replay");
    let trace_read = create_temp_trace_path("v3_read_replay");
    let input_file = PathBuf::from("/tmp/causal_m5_v3_input.txt");
    fs::write(&input_file, b"CAUSAL_M4_PAYLOAD_21B").unwrap();

    let res_rec = run_tracee(
        fixture_read.to_str().unwrap(),
        &[input_file.to_str().unwrap().to_string()],
        Some(&trace_read),
    );
    assert_eq!(res_rec, Ok(TraceeTermination::Exited(0)));

    let parsed_read = read_trace_file_versioned(&trace_read).unwrap();
    assert_eq!(parsed_read.version, TRACE_VERSION_3);

    // Corrupt input source file
    fs::write(&input_file, b"CORRUPTED INPUT FOR LIVE READ EXECUTION").unwrap();

    // Replay must succeed via substitution while skipping map metadata
    let replay_res = run_replay(
        &trace_read,
        fixture_read.to_str().unwrap(),
        &[input_file.to_str().unwrap().to_string()],
    );
    assert_eq!(replay_res, Ok(TraceeTermination::Exited(0)));

    // 2. Mixed getpid + read replay under V3 trace
    let fixture_mixed = get_fixture_path("mixed_replay");
    let trace_mixed = create_temp_trace_path("v3_mixed_replay");
    let mixed_input = PathBuf::from("/tmp/causal_m5_v3_mixed_input.txt");
    fs::write(&mixed_input, b"CAUSAL_M4_PAYLOAD_21B").unwrap();

    let res_mixed_rec = run_tracee(
        fixture_mixed.to_str().unwrap(),
        &[mixed_input.to_str().unwrap().to_string()],
        Some(&trace_mixed),
    );
    assert_eq!(res_mixed_rec, Ok(TraceeTermination::Exited(0)));

    let parsed_mixed = read_trace_file_versioned(&trace_mixed).unwrap();
    assert_eq!(parsed_mixed.version, TRACE_VERSION_3);

    // Replay mixed trace
    let res_mixed_rep = run_replay(
        &trace_mixed,
        fixture_mixed.to_str().unwrap(),
        &[mixed_input.to_str().unwrap().to_string()],
    );
    assert_eq!(res_mixed_rep, Ok(TraceeTermination::Exited(0)));

    // 3. V3 replay stress: 25 getpid replays + 25 read replays
    let fixture_getpid = get_fixture_path("getpid_replay");
    let trace_getpid = create_temp_trace_path("v3_getpid_stress");
    let res_getpid_rec = run_tracee(fixture_getpid.to_str().unwrap(), &[], Some(&trace_getpid));
    assert_eq!(res_getpid_rec, Ok(TraceeTermination::Exited(0)));

    for i in 1..=25 {
        let rep = run_replay(&trace_getpid, fixture_getpid.to_str().unwrap(), &[]);
        assert_eq!(
            rep,
            Ok(TraceeTermination::Exited(0)),
            "getpid replay iteration {} failed",
            i
        );
    }

    for i in 1..=25 {
        let rep = run_replay(
            &trace_read,
            fixture_read.to_str().unwrap(),
            &[input_file.to_str().unwrap().to_string()],
        );
        assert_eq!(
            rep,
            Ok(TraceeTermination::Exited(0)),
            "read replay iteration {} failed",
            i
        );
    }

    let _ = fs::remove_file(&trace_read);
    let _ = fs::remove_file(&trace_mixed);
    let _ = fs::remove_file(&trace_getpid);
    let _ = fs::remove_file(&input_file);
    let _ = fs::remove_file(&mixed_input);
}

// ---------------------------------------------------------------------------
// 6. Stress Test: 100-Run Recording Loop
// ---------------------------------------------------------------------------

#[test]
fn test_m5_recording_stress_100_runs() {
    let fixture = get_fixture_path("map_model");
    let trace_path = create_temp_trace_path("stress_100");

    for i in 1..=100 {
        let res = run_tracee(fixture.to_str().unwrap(), &[], Some(&trace_path));
        assert_eq!(
            res,
            Ok(TraceeTermination::Exited(0)),
            "iteration {} failed",
            i
        );

        let parsed = read_trace_file_versioned(&trace_path).unwrap();
        assert_eq!(parsed.version, TRACE_VERSION_3);
        assert!(!parsed.events.is_empty());

        let _ = fs::remove_file(&trace_path);
    }
}
