use std::{error::Error, process::ExitCode};

fn main() -> ExitCode {
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
