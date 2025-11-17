// Browser automation functionality - to be implemented in future phases

mod chrome_finder;
mod error;
mod launcher;
mod profile;

pub use chrome_finder::ChromeFinder;
pub use error::{Error, Result};
pub use launcher::ChromeLauncher;
pub use profile::ProfileManager;
