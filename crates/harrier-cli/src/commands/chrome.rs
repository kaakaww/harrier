use anyhow::Result;
use std::path::{Path, PathBuf};

pub fn execute(
    output: &Path,
    hosts: Vec<String>,
    scan: bool,
    chrome_path: Option<PathBuf>,
    url: Option<String>,
    profile: Option<String>,
) -> Result<()> {
    println!("🚀 Chrome command");
    println!("  Output: {}", output.display());
    println!("  Hosts: {:?}", hosts);
    println!("  Scan: {}", scan);
    println!("  Chrome path: {:?}", chrome_path);
    println!("  URL: {:?}", url);
    println!("  Profile: {:?}", profile);

    Ok(())
}
