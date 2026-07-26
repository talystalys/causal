pub mod trace;
pub mod tracer;

use std::env;
use std::path::Path;
use std::process;

fn print_usage() {
    eprintln!("Usage: causal record [-o <trace>] <program> [args...]");
    eprintln!("       causal dump <trace>");
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
        _ => {
            print_usage();
            process::exit(2);
        }
    }
}
