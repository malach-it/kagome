use std::io::{self, Read, Write};

fn main() -> io::Result<()> {
    let mut request = String::new();
    io::stdin().read_to_string(&mut request)?;

    let response = kagome::handlers::echo::handle(&request);
    io::stdout().write_all(response.as_bytes())
}
