extern crate cellar_core;
use anyhow::Result;
use structopt::StructOpt;
use tokio::runtime::Runtime;

pub mod commands;
pub use commands::{Command, ConfigFile};

fn main() -> Result<()> {
    let mut rt = Runtime::new().unwrap();
    let cmd = Command::from_args();

    let fut = async {
        match cmd {
            Command::Init {
                config_file: ConfigFile { name },
            } => commands::init(&name).await,
            Command::Generate {
                config_file: ConfigFile { name },
                app_info,
            } => commands::generate(&name, &app_info).await,
        }
    };

    if let Err(err) = rt.block_on(fut) {
        eprintln!("{}", err);
        std::process::exit(1);
    }

    Ok(())
}
