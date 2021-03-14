use chrono::{DateTime, Utc};
use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, CustomExtension,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType, SignatureAlgorithm,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, net::IpAddr, str::FromStr};

use crate::{as_parent_key, generate_app_key_by_path, CellarError, KeyType};

#[derive(Debug, Clone)]
pub enum CertType {
    CA,
    Server,
    Client,
}

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub(crate) algo: Algo,
    pub(crate) domains: Vec<String>,
    pub(crate) org: String,
    pub(crate) common: String,
    pub(crate) country: String,
    pub(crate) start: DateTime<Utc>,
    pub(crate) days: Option<i64>,
    pub(crate) cert_type: CertType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificatePem {
    pub cert: String,
    pub sk: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algo {
    Ec,
    Ed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Usage {
    None,
    Ca,
    Cert,
}

const OID_ORG_UNIT: &[u64] = &[2, 5, 4, 11];
const OID_BASIC: &[u64] = &[2, 5, 29, 19];

const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];

const KEY_USAGE: &[Usage] = &[
    Usage::Cert, // digitalSignature
    Usage::Cert, // nonRepudiation/contentCommitment
    Usage::Cert, // keyEncipherment
    Usage::None,
    Usage::None,
    Usage::Ca, // keyCertSign
    Usage::Ca, // cRLSign
    Usage::None,
    Usage::None,
];

impl Default for CertInfo {
    fn default() -> Self {
        Self {
            algo: Algo::Ed,
            domains: Vec::new(),
            org: "".to_owned(),
            common: "".to_owned(),
            country: "".to_owned(),
            start: date_time_ymd(2020, 1, 1),
            end: date_time_ymd(2030, 1, 1),
            cert_type: CertType::Server,
        }
    }
}

impl CertInfo {
    pub fn new<'a>(
        domains: impl AsRef<[&'a str]>,
        country: &str,
        org: &str,
        cn: &str,
        days: Option<i64>,
    ) -> Self {
        Self {
            algo: Algo::Ed,
            domains: domains.as_ref().iter().map(|d| d.to_string()).collect(),
            country: country.to_owned(),
            org: org.to_owned(),
            common: cn.to_owned(),
            days,
        }
    }
    pub fn algo(&self) -> &'static SignatureAlgorithm {
        match self.algo {
            Algo::Ec => &rcgen::PKCS_ECDSA_P256_SHA256,
            Algo::Ed => &rcgen::PKCS_ED25519,
        }
    }

    pub fn key_type(&self) -> KeyType {
        match self.algo {
            Algo::Ec => KeyType::Pkcs8,
            Algo::Ed => KeyType::Pkcs8,
        }
    }

    pub fn path(&self) -> String {
        // TODO: client certificate only have one per domain here. Need to redesign if we really use client cert.
        match self.cert_type {
            CertType::CA => "/certificate/ca".to_owned(),
            CertType::Server => format!("/certificate/server/{}", self.domains[0]),
            CertType::Client => format!("/certificate/client/{}", self.domains[0]),
        }
    }

    fn distinguished_name(&self) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        let common_name = &self.domains[0];
        dn.push(DnType::CountryName, self.country.to_owned());

        dn.push(DnType::OrganizationName, self.org.to_owned());
        dn.push(
            DnType::from_oid(OID_ORG_UNIT),
            format!("{} from {}", common_name, self.org),
        );
        dn.push(DnType::CommonName, common_name.to_owned());
        dn
    }

    fn distinguished_name_ca(&self) -> DistinguishedName {
        let mut dn = DistinguishedName::new();
        let common_name = "lit.ca";
        dn.push(DnType::CountryName, "US".to_owned());

        dn.push(DnType::OrganizationName, "Lit".to_owned());
        dn.push(
            DnType::from_oid(OID_ORG_UNIT),
            format!("{} from Lit", common_name),
        );
        dn.push(DnType::CommonName, common_name.to_owned());
        dn
    }

    fn subject_alt_names(&self) -> Vec<SanType> {
        self.domains
            .iter()
            .map(|d| {
                if let Ok(ip) = IpAddr::from_str(d) {
                    SanType::IpAddress(ip)
                } else {
                    SanType::DnsName(d.to_owned())
                }
            })
            .collect()
    }

    fn key_usage_purpose(&self) -> ExtendedKeyUsagePurpose {
        match self.cert_type {
            CertType::Server => ExtendedKeyUsagePurpose::ServerAuth,
            CertType::Client => ExtendedKeyUsagePurpose::ClientAuth,
            CertType::CA => ExtendedKeyUsagePurpose::Any,
        }
    }
}

/// generate CA certificate from the parent_key and domain name
pub fn generate_ca_cert(parent_key: &[u8]) -> Result<CertificatePem, CellarError> {
    let info = CertInfo {
        cert_type: CertType::CA,
        ..Default::default()
    };

    generate_cert(parent_key, &info)
}

/// generate server certificate from the parent_key, domain name, and organization name
pub fn generate_server_cert(
    parent_key: &[u8],
    domain: &str,
    org: &str,
) -> Result<CertificatePem, CellarError> {
    let info = CertInfo {
        cert_type: CertType::Server,
        org: org.to_owned(),
        domains: vec![domain.to_owned()],
        ..Default::default()
    };

    generate_cert(parent_key, &info)
}

/// generate a certificate with parent key and pre-filled certificate info.
pub fn generate_cert(parent_key: &[u8], info: &CertInfo) -> Result<CertificatePem, CellarError> {
    let keypair = get_keypair(parent_key, info.key_type(), &info.path())?;
    let sn = get_serial_number(keypair.public_key_raw());

    let mut params: CertificateParams = Default::default();
    params.alg = info.algo();
    params.serial_number = Some(sn);
    params.not_before = info.start;
    params.not_after = info.end;

    params.key_pair = Some(keypair);

    let cert = match info.cert_type {
        CertType::CA => {
            params.distinguished_name = info.distinguished_name_ca();
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(16));
            params.custom_extensions.push(key_usage(true));
            let cert = Certificate::from_params(params)?;
            CertificatePem {
                cert: cert.serialize_pem()?,
                sk: cert.serialize_private_key_pem(),
            }
        }
        _ => {
            params.distinguished_name = info.distinguished_name();
            params.subject_alt_names = info.subject_alt_names();
            params.custom_extensions.push(not_ca());
            params.custom_extensions.push(key_usage(false));
            params.extended_key_usages.push(info.key_usage_purpose());
            let cert = Certificate::from_params(params)?;

            let ca = load_ca(parent_key, info)?;
            CertificatePem {
                cert: cert.serialize_pem_with_signer(&ca)?,
                sk: cert.serialize_private_key_pem(),
            }
        }
    };

    Ok(cert)
}

fn get_keypair(parent_key: &[u8], key_type: KeyType, path: &str) -> Result<KeyPair, CellarError> {
    let parent = as_parent_key(parent_key);
    let data = generate_app_key_by_path(parent, path, key_type)?;
    let key_pair = KeyPair::try_from(&data[..])?;
    Ok(key_pair)
}

fn get_serial_number(pk: &[u8]) -> u64 {
    let hash = blake3::hash(pk);
    let bytes = hash.as_bytes();
    let mut data = [0u8; 8];
    data.copy_from_slice(&bytes[8..16]);
    u64::from_le_bytes(data)
}

fn load_ca(parent_key: &[u8], info: &CertInfo) -> Result<Certificate, CellarError> {
    let ca_info = {
        let mut v = info.clone();
        v.cert_type = CertType::CA;
        v
    };
    let cert_pem = generate_cert(parent_key, &ca_info)?;
    let keypair = KeyPair::from_pem(&cert_pem.sk)?;

    let params = CertificateParams::from_ca_cert_pem(&cert_pem.cert, keypair)?;
    let cert = Certificate::from_params(params)?;
    Ok(cert)
}

fn key_usage(ca: bool) -> CustomExtension {
    let der = yasna::construct_der(|writer| {
        writer.write_bitvec(
            &KEY_USAGE
                .iter()
                .map(|u| *u == if ca { Usage::Ca } else { Usage::Cert })
                .collect(),
        );
    });

    let mut key_usage = CustomExtension::from_oid_content(OID_KEY_USAGE, der);
    key_usage.set_criticality(true);
    key_usage
}

fn not_ca() -> CustomExtension {
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bool(false);
        });
    });

    CustomExtension::from_oid_content(OID_BASIC, der)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generate_ca_cert_should_work() -> Result<(), CellarError> {
        let parent_key = [0u8; 32];
        let pem = generate_ca_cert(&parent_key)?;
        println!("{}", pem.cert);
        println!("{}", pem.sk);
        Ok(())
    }

    #[test]
    fn generate_server_cert_should_work() -> Result<(), CellarError> {
        let parent_key = [0u8; 32];
        let pem = generate_server_cert(&parent_key, "sigma.city", "Sigma")?;
        println!("{}", pem.cert);
        println!("{}", pem.sk);
        Ok(())
    }
}
