use std::io;

fn main() -> io::Result<()> {
    let address = kagome::http_server::address_from_environment();
    let workers = kagome::http_server::worker_count_from_environment();

    kagome::http_server::serve_with_workers(address, workers)
}
