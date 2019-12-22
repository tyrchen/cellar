use anyhow::{anyhow, Result};
use cellar_core::AuxiliaryData;
use dialoguer::{theme::ColorfulTheme, PasswordInput};
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::fs;

fn parse_dir(src: &str) -> PathBuf {
    if src.starts_with("~/") {
        dirs::home_dir().unwrap().join(src.replace("~/", ""))
    } else {
        PathBuf::from(src)
    }
}

/// generate passphrase protected, crytographically strong application password that derived from master key
#[derive(StructOpt, Debug)]
#[structopt(name = "cellar")]
pub enum Command {
    /// initialize a cellar
    Init {
        #[structopt(flatten)]
        config_file: ConfigFile,
    },

    /// (re)generate application password
    Generate {
        #[structopt(flatten)]
        config_file: ConfigFile,
        /// application specific info, e.g. user@gmail.com
        #[structopt(short = "i", long)]
        app_info: String,
    },
}

#[derive(StructOpt, Debug)]
pub struct ConfigFile {
    /// Configuration file name
    #[structopt(
            name = "CONFIG_FILE",
            parse(from_str=parse_dir),
            default_value = "~/.cellar/default.toml"
        )]
    pub name: PathBuf,
}

pub async fn init(name: &PathBuf) -> Result<()> {
    if name.exists() {
        return Err(anyhow!(format!("You have already initialized your cellar. If you want to generate a new cellar, please change the config filename, or remove {:?} and try again.", name)));
    }
    println!("Creating cellar {:?}", name);

    let password = prompt_password(true)?;

    let aux = cellar_core::init(&password)?;
    let toml = toml::to_string(&aux)?;
    fs::create_dir_all(name.parent().unwrap()).await?;
    fs::write(name, toml).await?;
    println!("Your cellar {:?} is created! Feel free to use `cellar generate` to create or display your application password.", name);
    Ok(())
}

pub async fn generate(name: &PathBuf, app_info: &str) -> Result<()> {
    if !name.exists() {
        return Err(anyhow!(format!("Configuration file {:?} doesn't exist. Please make sure you have initialized your cellar. See `cellar init --help` for more information.", name)));
    }

    let content = fs::read_to_string(name).await?;
    let aux: AuxiliaryData = toml::from_str(&content)?;
    let password = prompt_password(false)?;

    let info = app_info.as_bytes();
    let app_key = cellar_core::generate_app_key(&password, &aux, info)?;
    println!("Password for {}: {}", app_info, app_key);
    Ok(())
}

#[inline]
fn prompt_password(confirmation: bool) -> Result<String> {
    let password = if confirmation {
        PasswordInput::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .with_confirmation("Repeat password", "Error: the passwords don't match.")
            .interact()?
    } else {
        PasswordInput::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .interact()?
    };

    Ok(password)
}
