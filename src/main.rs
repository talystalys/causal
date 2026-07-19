use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: causal <command> [args...]");
        return ExitCode::from(1);
    }
    match args[1].as_str() {
        "run" => {
            if args.len() < 3 {
                eprintln!("Usage: causal run <target> [args...]");
                return ExitCode::from(1);
            }
            let target = &args[2];
            let target_args = &args[3..];
            match causal::tracer::run_tracee(target, target_args, None) {
                Ok(exit_code) => ExitCode::from(exit_code as u8),
                Err(e) => {
                    eprintln!("causal: {}", e);
                    ExitCode::from(1)
                }
            }
        }
        cmd => {
            eprintln!("causal: unknown command '{}'", cmd);
            ExitCode::from(1)
        }
    }
}
