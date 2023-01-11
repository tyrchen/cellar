use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use cellar_core::{AuxiliaryData, KeyType};
use dialoguer::{theme::ColorfulTheme, Password};
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

fn parse_type(src: &str) -> Result<Box<KeyType>> {
    match src {
        "password" => Ok(Box::new(KeyType::Password)),
        // "keypair" => Ok(Box::new(KeyType::Keypair)),
        // "certificate" => Ok(KeyType::Certificate),
        &_ => Err(anyhow!(format!(
            "Invalid key type {}. Available choices: password",
            src
        ))),
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
        /// generated key type - password or keypair
        #[structopt(short = "t", parse(try_from_str=parse_type), default_value="password")]
        key_type: Box<KeyType>,
        /// use parent key instead of password
        #[structopt(long)]
        use_parent_key: bool,
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

pub async fn generate(
    name: &PathBuf,
    app_info: &str,
    key_type: KeyType,
    use_parent_key: bool,
) -> Result<()> {
    if !name.exists() {
        return Err(anyhow!(format!("Configuration file {:?} doesn't exist. Please make sure you have initialized your cellar. See `cellar init --help` for more information.", name)));
    }

    let parent_key = if use_parent_key {
        let parent_key_str = prompt_parent_key()?;
        let data = URL_SAFE_NO_PAD.decode(parent_key_str)?;
        cellar_core::as_parent_key(&data)
    } else {
        let content = fs::read_to_string(name).await?;
        let aux: AuxiliaryData = toml::from_str(&content)?;
        let password = prompt_password(false)?;

        cellar_core::generate_master_key(&password, &aux)?
    };

    let app_key = cellar_core::generate_app_key_by_path(parent_key, app_info, key_type)?;
    println!("Key for {}: {}", app_info, URL_SAFE_NO_PAD.encode(app_key));
    Ok(())
}

#[inline]
fn prompt_password(confirmation: bool) -> Result<String> {
    let password = if confirmation {
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .with_confirmation("Repeat password", "Error: the passwords don't match.")
            .interact()?
    } else {
        Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Password")
            .interact()?
    };

    Ok(password)
}

#[inline]
fn prompt_parent_key() -> Result<String> {
    let key = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Parent Key")
        .interact()?;

    Ok(key)
}
