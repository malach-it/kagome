use std::{env, error::Error, ffi::OsStr, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    if args.next().as_deref() == Some(OsStr::new("--ssh-command")) {
        return match (args.next(), args.next()) {
            (Some(encoded), None) => encoded.to_str().map_or(ExitCode::from(126), |encoded| {
                kagome::resources::agent_ssh::run_registered_command(encoded)
            }),
            _ => ExitCode::from(126),
        };
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = kagome::config::Config::initialize()?;
    println!("{}", config.redacted_summary());
    kagome::templates::initialize()?;

    kagome::http_server::serve_with_workers(&config.server.address, config.server.workers)?;

    Ok(())
}
