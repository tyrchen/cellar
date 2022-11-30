//! Cellar is a simple password generation / retrieval tool inspired by Technology Preview for secure value recovery. The main algorithm is (a little bit tweak against original one):
//!
//! ```bash
//! salt            = Secure-Random(output_length=32)
//! stretched_key   = Argon2(passphrase=user_passphrase, salt=salt)
//!
//! auth_key        = HMAC-BLAKE2s(key=stretched_key, "Auth Key")
//! c1              = HMAC-BLAKE2s(key=stretched_key, "Master Key")
//! c2              = Secure-Random(output_length=32)
//! encrypted_c2    = ChaCha20(c2, key=auth_key, nonce=salt[0..CHACHA20_NONCE_LENGTH])
//!
//! master_key      = HMAC-BLAKE2s(key=c1, c2)
//! application_key = HMAC-BLAKE2s(key=master_key, "app info, e.g. yourname@gmail.com")
//! ```
//!
//! The main purpose of cellar is to allow people to just remember a single password, and by using the above algorithm, one can create as many application passwords which is cryptographically strong. A user just need to store the randomly gnerated salt and encrypted_c2 in local disk and the cloud so when she wants to generate or retrieve an application password, she could use her passphrase, plus the salt and encrypted_c2 to recover the master key, and then derive the application password. As long as user kept the passphrase secret in her mind, all the application passwords are secure. Even if the salt and encrypted_c2 are leaked, a hacker still need to brute force the master key.

//! By using Cellar, you don't need to trust the cloud provider to store your passwords, and you don't need to bother to remember a large number of passwords for different sites / applications.
//!
//! ## Usage
//! ```rust
//! let passphrase = "hello";
//! let aux = cellar_core::init(passphrase).unwrap();
//! let app_key = cellar_core::generate_app_key(passphrase, &aux, b"user@gmail.com", Default::default()).unwrap();
//! ```
//!
//! You can also use the CLI version of the tool, which could be found in the repository.
use base64::URL_SAFE_NO_PAD;
use blake2s_simd::Params;
use c2_chacha::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use c2_chacha::ChaCha20;
use certify::{CertInfo, KeyPair, CA};
use ed25519_compact::{KeyPair as Ed25519KeyPair, Seed as Ed25519Seed};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

mod error;
pub use error::CellarError;

pub const KEY_SIZE: usize = 32;
pub type Key = Zeroizing<[u8; KEY_SIZE]>;

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, PartialEq, Eq)]
#[zeroize(drop)]
pub struct AuxiliaryData {
    salt: String,
    encrypted_seed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePem {
    pub cert: String,
    pub sk: String,
}

#[derive(Debug, Clone)]
pub enum KeyType {
    Password,
    Keypair,
    CA(CertInfo),
    ServerCert((String, String, CertInfo)),
    ClientCert((String, String, CertInfo)),
}

impl Default for KeyType {
    fn default() -> Self {
        KeyType::Password
    }
}

impl AuxiliaryData {
    pub fn new(salt: &str, seed: &str) -> Self {
        Self {
            salt: salt.to_owned(),
            encrypted_seed: seed.to_owned(),
        }
    }
}

const AUTH_KEY_INFO: &[u8] = b"Auth Key";
const MASTER_KEY_INFO: &[u8] = b"Master Key";
const CHACHA20_NONCE_LENGTH: usize = 8;

/// generate random passphrase
pub fn random_passphrase() -> String {
    let mut rng = StdRng::from_entropy();
    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    base64::encode_config(buf, URL_SAFE_NO_PAD)
}

/// initialize a cellar. Return the salt and encrypted seed that user shall store them for future password generation and retrieval.
pub fn init(passphrase: &str) -> Result<AuxiliaryData, CellarError> {
    let mut rng = StdRng::from_entropy();
    let mut salt: Key = Zeroizing::new([0u8; KEY_SIZE]);
    let mut seed: Key = Zeroizing::new([0u8; KEY_SIZE]);

    rng.fill_bytes(salt.as_mut());
    rng.fill_bytes(seed.as_mut());

    let stretch_key = generate_stretch_key(passphrase, salt.as_ref())?;
    let auth_key = generate_derived_key(&stretch_key, AUTH_KEY_INFO);

    let mut encrypted_seed = seed.as_ref().to_vec();
    let nonce = &salt[..CHACHA20_NONCE_LENGTH];
    let mut cipher = ChaCha20::new_var(auth_key.as_ref(), nonce).unwrap();
    cipher.apply_keystream(&mut encrypted_seed);

    Ok(AuxiliaryData {
        salt: base64::encode_config(salt.as_ref(), URL_SAFE_NO_PAD),
        encrypted_seed: base64::encode_config(&encrypted_seed, URL_SAFE_NO_PAD),
    })
}

/// generate master key from the passphrase and entropy
pub fn generate_master_key(passphrase: &str, aux: &AuxiliaryData) -> Result<Key, CellarError> {
    let salt = base64::decode_config(&aux.salt, URL_SAFE_NO_PAD)?;
    let mut seed = base64::decode_config(&aux.encrypted_seed, URL_SAFE_NO_PAD)?;

    // stretch the passphrase to 32 bytes long
    let stretch_key = generate_stretch_key(passphrase, &salt)?;

    // generate a not so strong auth key for encrypting the secure random
    let auth_key = generate_derived_key(&stretch_key, AUTH_KEY_INFO);

    // generate master key main part
    let partial_key = generate_derived_key(&stretch_key, MASTER_KEY_INFO);

    // recover master seed
    let nonce = &salt[..CHACHA20_NONCE_LENGTH];
    let mut cipher = ChaCha20::new_var(auth_key.as_ref(), nonce).unwrap();
    cipher.apply_keystream(&mut seed);

    // recover master key
    let master_key = generate_derived_key(&partial_key, &seed);
    Ok(master_key)
}

/// generate application key based on user's passphrase, auxiliary data (salt and seed), as well as the app info as an entropy.
pub fn generate_app_key(
    passphrase: &str,
    aux: &AuxiliaryData,
    info: &[u8],
    key_type: KeyType,
) -> Result<Vec<u8>, CellarError> {
    let master_key = generate_master_key(passphrase, aux)?;
    let app_key = generate_derived_key(&master_key, info);
    generate_by_key_type(app_key, key_type)
}

/// generate application key based on parent key and path. e.g. `apps/my/awesome/app`.
pub fn generate_app_key_by_path(
    parent_key: Key,
    path: &str,
    key_type: KeyType,
) -> Result<Vec<u8>, CellarError> {
    //let sum = a.iter().fold(0, |acc, x| acc + x);
    let app_key = path.split('/').fold(parent_key, |acc, part| {
        generate_derived_key(&acc, part.as_bytes())
    });
    generate_by_key_type(app_key, key_type)
}

pub fn to_base64(key: &[u8]) -> String {
    base64::encode_config(key, URL_SAFE_NO_PAD)
}

pub fn from_base64(key: &str) -> Result<Key, CellarError> {
    let data = base64::decode_config(key, URL_SAFE_NO_PAD)?;

    let key: [u8; KEY_SIZE] = data
        .try_into()
        .map_err(|_e| CellarError::InvalidKey("Cannot convert the Vec<u8> to Key".to_owned()))?;
    Ok(key.into())
}

/// covert the generated application key to a parent key which could be used to derive other keys
pub fn as_parent_key(app_key: &[u8]) -> Key {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(app_key);
    key
}

#[inline]
fn generate_stretch_key(passphrase: &str, salt: &[u8]) -> Result<Key, CellarError> {
    let hash = argon2::hash_raw(passphrase.as_bytes(), salt, &argon2::Config::default())?;
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&hash);
    Ok(key)
}

#[inline]
fn generate_derived_key(stretch_key: &Key, info: &[u8]) -> Key {
    let mut params = Params::new();
    params.key(stretch_key.as_ref());
    let hash = params.hash(info).as_array().to_owned();
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&hash);
    key
}

#[inline]
fn generate_by_key_type(app_key: Key, key_type: KeyType) -> Result<Vec<u8>, CellarError> {
    match key_type {
        KeyType::Password => Ok(Vec::from(&app_key[..])),
        KeyType::Keypair => {
            let keypair = Ed25519KeyPair::from_seed(Ed25519Seed::from_slice(app_key.as_ref())?);
            Ok(keypair.as_slice().to_vec())
        }
        KeyType::CA(info) => {
            let key = Ed25519KeyPair::from_seed(Ed25519Seed::from_slice(app_key.as_ref())?);
            let keypair = KeyPair::from_der(&key.sk.to_der())?;
            let ca = info.ca_cert(Some(keypair))?;
            let cert_pem = CertificatePem {
                cert: ca.serialize_pem().unwrap(),
                sk: ca.serialize_private_key_pem(),
            };
            Ok(bincode::serialize(&cert_pem)?)
        }
        KeyType::ServerCert((ca_pem, key_pem, info)) => {
            let ca = CA::load(&ca_pem, &key_pem)?;
            let key = Ed25519KeyPair::from_seed(Ed25519Seed::from_slice(app_key.as_ref())?);
            let keypair = KeyPair::from_der(&key.sk.to_der())?;
            let cert = info.server_cert(Some(keypair))?;
            let (server_cert_pem, server_key_pem) = ca.sign_cert(&cert)?;
            let cert_pem = CertificatePem {
                cert: server_cert_pem,
                sk: server_key_pem,
            };
            Ok(bincode::serialize(&cert_pem)?)
        }
        KeyType::ClientCert((ca_pem, key_pem, info)) => {
            let ca = CA::load(&ca_pem, &key_pem)?;
            let key = Ed25519KeyPair::from_seed(Ed25519Seed::from_slice(app_key.as_ref())?);
            let keypair = KeyPair::from_der(&key.sk.to_der())?;
            let cert = info.client_cert(Some(keypair))?;
            let (server_cert_pem, server_key_pem) = ca.sign_cert(&cert)?;
            let cert_pem = CertificatePem {
                cert: server_cert_pem,
                sk: server_key_pem,
            };
            Ok(bincode::serialize(&cert_pem)?)
        }
    }
}

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(test)]
mod tests {
    use super::*;
    use certify::CertSigAlgo;

    #[test]
    fn same_passphrase_produce_same_keys() -> Result<(), CellarError> {
        let passphrase = "hello";
        let aux = init(passphrase)?;
        let app_key = generate_app_key(passphrase, &aux, b"user@gmail.com", KeyType::Password)?;
        let app_key1 = generate_app_key(passphrase, &aux, b"user1@gmail.com", KeyType::Password)?;

        assert_ne!(app_key1, app_key);

        let app_key2 = generate_app_key(passphrase, &aux, b"user@gmail.com", KeyType::Password)?;
        assert_eq!(app_key2, app_key);
        Ok(())
    }

    #[test]
    fn generate_usable_keypair_should_work() -> Result<(), CellarError> {
        let passphrase = "hello";
        let aux = init(passphrase)?;
        let key = generate_app_key(passphrase, &aux, b"user@gmail.com", KeyType::Keypair)?;

        let keypair = Ed25519KeyPair::from_slice(&key).unwrap();
        let content = b"hello world";
        let sig = keypair.sk.sign(content, None);
        let verified = keypair.pk.verify(content, &sig);
        assert!(verified.is_ok());
        Ok(())
    }

    #[test]
    fn generate_key_by_path_should_work() -> Result<(), CellarError> {
        let passphrase = "hello";
        let aux = init(passphrase)?;
        let key = generate_master_key(passphrase, &aux)?;
        let parent_key = generate_app_key(passphrase, &aux, b"apps", KeyType::Password)?;
        let app_key = generate_app_key_by_path(key, "apps/my/awesome/key", KeyType::Password)?;
        let app_key1 = generate_app_key_by_path(
            as_parent_key(&parent_key),
            "my/awesome/key",
            KeyType::Password,
        )?;
        assert_eq!(app_key, app_key1);
        Ok(())
    }

    #[test]
    fn generate_ca_cert_should_work() -> Result<(), CellarError> {
        let info = CertInfo::new(
            vec!["localhost"],
            Vec::<String>::new(),
            "US",
            "Domain Inc.",
            "Domain CA",
            None,
            CertSigAlgo::ED25519,
        );
        let (_, parent_key, cert_pem) = generate_ca(info.clone())?;

        CA::load(&cert_pem.cert, &cert_pem.sk)?;

        let cert1 = generate_app_key_by_path(
            as_parent_key(&parent_key),
            "localhost/ca",
            KeyType::CA(info),
        )?;

        let cert_pem1: CertificatePem = bincode::deserialize(&cert1)?;

        assert_eq!(&cert_pem.sk, &cert_pem1.sk);
        assert_eq!(&cert_pem.cert, &cert_pem1.cert);

        Ok(())
    }

    #[test]
    fn generate_server_cert_should_work() -> Result<(), CellarError> {
        let info = CertInfo::new(
            vec!["localhost"],
            Vec::<String>::new(),
            "US",
            "Domain Inc.",
            "Domain CA",
            None,
            CertSigAlgo::ED25519,
        );
        let (key, parent_key, cert_pem) = generate_ca(info)?;

        let info = CertInfo::new(
            vec!["localhost"],
            Vec::<String>::new(),
            "US",
            "Domain Inc.",
            "GRPC Server",
            Some(365),
            CertSigAlgo::ED25519,
        );
        let cert = generate_app_key_by_path(
            key,
            "apps/localhost/server",
            KeyType::ServerCert((cert_pem.cert.clone(), cert_pem.sk.clone(), info.clone())),
        )?;

        let cert1 = generate_app_key_by_path(
            as_parent_key(&parent_key),
            "localhost/server",
            KeyType::ServerCert((cert_pem.cert.clone(), cert_pem.sk.clone(), info)),
        )?;

        println!("{}\n{}", &cert_pem.cert, &cert_pem.sk);

        let cert_pem: CertificatePem = bincode::deserialize(&cert)?;
        println!("{}\n{}", &cert_pem.cert, &cert_pem.sk);

        assert_eq!(cert, cert1);

        Ok(())
    }

    #[test]
    fn generate_client_cert_should_work() -> Result<(), CellarError> {
        let info = CertInfo::new(
            vec!["localhost"],
            Vec::<String>::new(),
            "US",
            "Domain Inc.",
            "Domain CA",
            None,
            CertSigAlgo::ED25519,
        );
        let (key, parent_key, ca_cert_pem) = generate_ca(info)?;

        println!("CA cert:\n\n{}\n{}", &ca_cert_pem.cert, &ca_cert_pem.sk);

        let info = CertInfo::new(
            vec!["localhost"],
            Vec::<String>::new(),
            "US",
            "Domain Inc.",
            "GRPC Server",
            Some(365),
            CertSigAlgo::ED25519,
        );
        let server_cert = generate_app_key_by_path(
            as_parent_key(&parent_key),
            "localhost/server",
            KeyType::ServerCert((ca_cert_pem.cert.clone(), ca_cert_pem.sk.clone(), info)),
        )?;

        let server_cert_pem: CertificatePem = bincode::deserialize(&server_cert)?;
        println!(
            "Server cert:\n\n{}\n{}",
            &server_cert_pem.cert, &server_cert_pem.sk
        );

        let info = CertInfo::new(
            vec!["localhost"],
            Vec::<String>::new(),
            "US",
            "android",
            "abcd1234",
            Some(180),
            CertSigAlgo::ED25519,
        );
        let client_cert = generate_app_key_by_path(
            key,
            "apps/localhost/client/abcd1234",
            KeyType::ClientCert((
                ca_cert_pem.cert.clone(),
                ca_cert_pem.sk.clone(),
                info.clone(),
            )),
        )?;

        let cert1 = generate_app_key_by_path(
            as_parent_key(&parent_key),
            "localhost/client/abcd1234",
            KeyType::ClientCert((ca_cert_pem.cert.clone(), ca_cert_pem.sk, info)),
        )?;

        let client_cert_pem: CertificatePem = bincode::deserialize(&client_cert)?;
        println!(
            "Client cert:\n\n{}\n{}",
            &client_cert_pem.cert, &client_cert_pem.sk
        );

        assert_eq!(client_cert, cert1);

        Ok(())
    }

    #[ignore]
    #[quickcheck]
    fn prop_same_passphrase_produce_same_keys(passphrase: String, app_info: String) -> bool {
        let aux = init(&passphrase).unwrap();
        let app_key =
            generate_app_key(&passphrase, &aux, app_info.as_bytes(), KeyType::Password).unwrap();

        app_key
            == generate_app_key(&passphrase, &aux, app_info.as_bytes(), KeyType::Password).unwrap()
    }

    fn generate_ca(info: CertInfo) -> Result<(Key, Vec<u8>, CertificatePem), CellarError> {
        let passphrase = "hello";
        let aux = init(passphrase)?;
        let key = generate_master_key(passphrase, &aux)?;
        let parent_key = generate_app_key(passphrase, &aux, b"apps", KeyType::Password)?;

        let cert = generate_app_key_by_path(key.clone(), "apps/localhost/ca", KeyType::CA(info))?;
        let cert_pem: CertificatePem = bincode::deserialize(&cert)?;
        Ok((key, parent_key, cert_pem))
    }
}
