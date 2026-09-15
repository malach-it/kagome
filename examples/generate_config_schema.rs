use std::error::Error;

use kagome::config::Config;

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", serde_json::to_string_pretty(&Config::json_schema())?);

    Ok(())
}
