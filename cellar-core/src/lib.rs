use base64::URL_SAFE_NO_PAD;
use blake2s_simd::Params;
use c2_chacha::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use c2_chacha::ChaCha20;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

mod error;
pub use error::CellarError;

pub type Key = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuxiliaryData {
    salt: String,
    encrypted_seed: String,
}

const AUTH_KEY_INFO: &[u8] = b"Auth Key";
const MASTER_KEY_INFO: &[u8] = b"Master Key";
const CHACHA20_NONCE_LENGTH: usize = 8;

pub fn init(passphrase: &str) -> Result<AuxiliaryData, CellarError> {
    let mut rng = StdRng::from_entropy();
    let mut salt: Key = Default::default();
    let mut seed: Key = Default::default();

    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut seed);

    let stretch_key = generate_stretch_key(passphrase, &salt)?;
    let auth_key = generate_derived_key(&stretch_key, AUTH_KEY_INFO);

    let mut encrypted_seed = seed.as_ref().to_vec();
    let nonce = &salt[..CHACHA20_NONCE_LENGTH];
    let mut cipher = ChaCha20::new_var(&auth_key, nonce).unwrap();
    cipher.apply_keystream(&mut encrypted_seed);

    Ok(AuxiliaryData {
        salt: base64::encode_config(&salt, URL_SAFE_NO_PAD),
        encrypted_seed: base64::encode_config(&encrypted_seed, URL_SAFE_NO_PAD),
    })
}

pub fn generate_app_key(
    passphrase: &str,
    aux: &AuxiliaryData,
    info: &[u8],
) -> Result<String, CellarError> {
    let master_key = generate_master_key(passphrase, aux)?;
    let app_key = generate_derived_key(&master_key, info);
    Ok(base64::encode_config(&app_key, URL_SAFE_NO_PAD))
}

#[inline]
fn generate_master_key(passphrase: &str, aux: &AuxiliaryData) -> Result<Key, CellarError> {
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
    let mut cipher = ChaCha20::new_var(&auth_key, nonce).unwrap();
    cipher.apply_keystream(&mut seed);

    // recover master key
    let master_key = generate_derived_key(&partial_key, &seed);
    Ok(master_key)
}

#[inline]
fn generate_stretch_key(passphrase: &str, salt: &[u8]) -> Result<Key, CellarError> {
    let hash = argon2::hash_raw(passphrase.as_bytes(), salt, &argon2::Config::default())?;
    let mut array: Key = Default::default();
    array.copy_from_slice(&hash);
    Ok(array)
}

#[inline]
fn generate_derived_key(stretch_key: &Key, info: &[u8]) -> Key {
    let mut params = Params::new();
    params.key(stretch_key);
    params.hash(info).as_array().to_owned()
}

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_passphrase_produce_same_keys() -> Result<(), CellarError> {
        let passphrase = "hello";
        let aux = init(passphrase)?;
        let app_key = generate_app_key(passphrase, &aux, "user@gmail.com".as_bytes())?;
        let app_key1 = generate_app_key(passphrase, &aux, "user1@gmail.com".as_bytes())?;

        assert_ne!(app_key1, app_key);

        let app_key2 = generate_app_key(passphrase, &aux, "user@gmail.com".as_bytes())?;
        assert_eq!(app_key2, app_key);
        Ok(())
    }

    #[quickcheck]
    fn prop_same_passphrase_produce_same_keys(passphrase: String, app_info: String) -> bool {
        let aux = init(&passphrase).unwrap();
        let app_key = generate_app_key(&passphrase, &aux, &app_info.as_bytes()).unwrap();

        app_key == generate_app_key(&passphrase, &aux, &app_info.as_bytes()).unwrap()
    }
}
