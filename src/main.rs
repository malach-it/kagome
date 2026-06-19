use std::io;

fn main() -> io::Result<()> {
    kagome::ca::ensure_ca_key(kagome::ca::ca_key_path_from_environment())?;

    let address = kagome::http_server::address_from_environment();
    let workers = kagome::http_server::worker_count_from_environment();

    kagome::http_server::serve_with_workers(address, workers)
}
