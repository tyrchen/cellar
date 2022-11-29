//! Cellar is a command line tool to generate derived application passwords from a single password.
//!
//! ## cellar init
//!
//! Initialize a cellar (default: `$HOME/.cellar/default.toml`)
//!
//! ```bash
//! $ cellar init
//! Creating cellar "$HOME/.cellar/default.toml"
//! Password: [hidden]
//! Your cellar "$HOME/.cellar/default.toml" is created! Feel free to use `cellar generate` to create or display your application password.
//! ```
//!
//! after initialization, a `~/.cellar/default.toml` is generated. This files stores the random salt and the encrypted random seed like this:
//!
//! ```bash
//! $ cat ~/.cellar/default.toml
//! salt = "C6TQW8joYp2XoIkvaCNfo0ihJ3OacxlTbx68_oW8pF4"
//! encrypted_seed = "bHn5Lu3yX0g68rRJ4lTOwAvx_uMDFaBnZ_WMkJSU8TM"
//! ```
//!
//! Note that even if you regenerate the cellar with the same password you will get very different master key and derived application keys. So make sure you backup this file into your private cloud.
//!
//! ## cellar generate
//!
//! Generate an application password.
//!
//! ```bash
//! $ cellar generate --app-info "user@gmail.com"
//! Password: [hidden]
//! Password for user@gmail.com: FLugCDPDQ5NP_Nb0whUMwY2YD3wMWqoGcoywqqZ_JSU
//! ```
extern crate cellar_core;
use anyhow::Result;
use structopt::StructOpt;
use tokio::runtime::Runtime;

pub mod commands;
pub use commands::{Command, ConfigFile};

fn main() -> Result<()> {
    let rt = Runtime::new()?;
    let cmd = Command::from_args();

    let fut = async {
        match cmd {
            Command::Init {
                config_file: ConfigFile { name },
            } => commands::init(&name).await,
            Command::Generate {
                config_file: ConfigFile { name },
                app_info,
                key_type,
                use_parent_key,
            } => commands::generate(&name, &app_info, *key_type, use_parent_key).await,
        }
    };

    if let Err(err) = rt.block_on(fut) {
        eprintln!("{}", err);
        std::process::exit(1);
    }

    Ok(())
}
