pub mod maps;
pub mod replay;
pub mod trace;
pub mod tracer;

use std::env;
use std::path::Path;
use std::process;

fn print_usage() {
    eprintln!("Usage: causal record [-o <trace>] <program> [args...]");
    eprintln!("       causal dump <trace>");
    eprintln!("       causal replay <trace> <program> [args...]");
    eprintln!("       causal maps <trace> <event-id>");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(2);
    }

    match args[1].as_str() {
        "record" => {
            let mut trace_path: Option<&Path> = None;
            let mut target_idx = 2;

            if target_idx < args.len()
                && (args[target_idx] == "-o" || args[target_idx] == "--output")
            {
                if target_idx + 1 >= args.len() {
                    print_usage();
                    process::exit(2);
                }
                trace_path = Some(Path::new(&args[target_idx + 1]));
                target_idx += 2;
            }

            if target_idx >= args.len() {
                print_usage();
                process::exit(2);
            }

            let target = &args[target_idx];
            let target_args = &args[target_idx + 1..];

            match tracer::run_tracee(target, target_args, trace_path) {
                Ok(tracer::TraceeTermination::Exited(code)) => {
                    process::exit(code);
                }
                Ok(tracer::TraceeTermination::Signaled(sig)) => {
                    process::exit(128 + sig);
                }
                Err(err) => {
                    eprintln!("causal: {}", err);
                    process::exit(1);
                }
            }
        }
        "dump" => {
            if args.len() != 3 {
                print_usage();
                process::exit(2);
            }
            let trace_file = &args[2];
            if let Err(err) = trace::dump_trace(trace_file) {
                eprintln!("causal: {}", err);
                process::exit(1);
            }
            process::exit(0);
        }
        "replay" => {
            if args.len() < 4 {
                print_usage();
                process::exit(2);
            }
            let trace_file = Path::new(&args[2]);
            let target = &args[3];
            let target_args = &args[4..];

            match replay::run_replay(trace_file, target, target_args) {
                Ok(tracer::TraceeTermination::Exited(code)) => {
                    process::exit(code);
                }
                Ok(tracer::TraceeTermination::Signaled(sig)) => {
                    process::exit(128 + sig);
                }
                Err(err) => {
                    eprintln!("causal: {}", err);
                    process::exit(1);
                }
            }
        }
        "maps" => {
            if args.len() != 4 {
                print_usage();
                process::exit(2);
            }
            let trace_file = &args[2];
            let event_id_str = &args[3];
            let event_id: u64 = match event_id_str.parse() {
                Ok(id) if id > 0 => id,
                _ => {
                    eprintln!("causal: invalid event-id '{}'", event_id_str);
                    process::exit(1);
                }
            };

            let parsed = match trace::read_trace_file_versioned(trace_file) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("causal: {}", err);
                    process::exit(1);
                }
            };

            match trace::reconstruct_maps_at_event(&parsed, event_id) {
                Ok(model) => {
                    for region in model.regions() {
                        println!("{}", region.format_maps_line());
                    }
                    process::exit(0);
                }
                Err(err) => {
                    eprintln!("causal: {}", err);
                    process::exit(1);
                }
            }
        }
        _ => {
            print_usage();
            process::exit(2);
        }
    }
}
