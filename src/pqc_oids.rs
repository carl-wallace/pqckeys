//! OIDs for PQC algorithms as captured here: <https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md>
//! ML-DSA and SLH-DSA object identifiers are relative to the `sigAlgs` arc as defined in the [NIST CSOR].
//!
//! ```text
//!    nistAlgorithms OBJECT IDENTIFIER ::= { joint-iso-itu-t(2)
//!      country(16) us(840) organization(1) gov(101) csor(3) 4 }
//!
//!    sigAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 3 }
//! ```
//! [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
#![allow(missing_docs)]

use const_oid::ObjectIdentifier;
use hex_literal::hex;

// HACKATHON OIDs (NON-STANDARD - DO NOT USE)
/// Falcon-512                    1.3.9999.3.6*
pub const OQ_FALCON_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.6");

/// Falcon-1024                    1.3.9999.3.9*
pub const OQ_FALCON_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.9");

//---------------------------------------------------------------------
// Definitions are from [draft-ietf-lamps-pq-composite-kem-07](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-07)
// and [draft-ietf-lamps-pq-composite-sigs-06](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-06).
//---------------------------------------------------------------------
pub const ID_MLKEM768_RSA2048_HMAC_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.50");
pub const ID_MLKEM768_RSA3072_HMAC_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.51");
pub const ID_MLKEM768_RSA4096_HMAC_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.52");
pub const ID_MLKEM768_X25519_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.53");
pub const ID_MLKEM768_ECDH_P256_HMAC_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.54");
pub const ID_MLKEM768_ECDH_P384_HMAC_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.55");
pub const ID_MLKEM768_ECDH_BRAINPOOL_P256R1_HMAC_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.56");
pub const ID_MLKEM768_RSA3072_HMAC_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.61");
pub const ID_MLKEM1024_ECDH_P384_HMAC_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.57");
pub const ID_MLKEM1024_ECDH_BRAINPOOL_P384R1_HMAC_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.58");
pub const ID_MLKEM1024_X448_SHA3_256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.59");
pub const ID_MLKEM1024_ECDH_P521_HMAC_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2.60");

pub const DS_MLKEM768_RSA2048_HMAC_SHA256: [u8; 13] = hex!("060B6086480186FA6B50050232");
pub const DS_MLKEM768_RSA3072_HMAC_SHA256: [u8; 13] = hex!("060B6086480186FA6B50050233");
pub const DS_MLKEM768_RSA4096_HMAC_SHA256: [u8; 13] = hex!("060B6086480186FA6B50050234");
pub const DS_MLKEM768_X25519_SHA3_256: [u8; 13] = hex!("060B6086480186FA6B50050235");
pub const DS_MLKEM768_ECDH_P256_HMAC_SHA256: [u8; 13] = hex!("060B6086480186FA6B50050236");
pub const DS_MLKEM768_ECDH_P384_HMAC_SHA256: [u8; 13] = hex!("060B6086480186FA6B50050237");
pub const DS_MLKEM768_ECDH_BRAINPOOL_P256R1_HMAC_SHA256: [u8; 13] = hex!("060B6086480186FA6B50050238");
pub const DS_MLKEM768_RSA3072_HMAC_SHA512: [u8; 13] = hex!("060B6086480186FA6B5005023D");
pub const DS_MLKEM1024_ECDH_P384_HMAC_SHA512: [u8; 13] = hex!("060B6086480186FA6B50050239");
pub const DS_MLKEM1024_ECDH_BRAINPOOL_P384R1_HMAC_SHA512: [u8; 13] = hex!("060B6086480186FA6B5005023A");
pub const DS_MLKEM1024_X448_SHA3_256: [u8; 13] = hex!("060B6086480186FA6B5005023B");
pub const DS_MLKEM1024_ECDH_P521_HMAC_SHA512: [u8; 13] = hex!("060B6086480186FA6B5005023C");


pub const ID_MLDSA44_RSA2048_PSS_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.0");
pub const ID_MLDSA44_RSA2048_PKCS15_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.1");
pub const ID_MLDSA44_ED25519_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.2");
pub const ID_MLDSA44_ECDSA_P256_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.3");
pub const ID_MLDSA65_RSA3072_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.4");
pub const ID_MLDSA65_RSA3072_PKCS15_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.5");
pub const ID_MLDSA65_RSA4096_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.6");
pub const ID_MLDSA65_RSA4096_PKCS15_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.7");
pub const ID_MLDSA65_ECDSA_P256_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.8");
pub const ID_MLDSA65_ECDSA_P384_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.9");
// pub const ID_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512: ObjectIdentifier =
//     ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.10");
pub const ID_MLDSA65_ED25519_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.11");
pub const ID_MLDSA87_ECDSA_P384_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.12");
// pub const ID_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512: ObjectIdentifier =
//     ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.13");
pub const ID_MLDSA87_ED448_SHAKE256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.14");
pub const ID_MLDSA87_RSA3072_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.15");
pub const ID_MLDSA87_RSA4096_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.16");
pub const ID_MLDSA87_ECDSA_P521_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.17");

pub const DS_MLDSA44_RSA2048_PSS_SHA256: [u8; 13] = hex!("060B6086480186FA6B50090100");
pub const DS_MLDSA44_RSA2048_PKCS15_SHA256: [u8; 13] = hex!("060B6086480186FA6B50090101");
pub const DS_MLDSA44_ED25519_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090102");
pub const DS_MLDSA44_ECDSA_P256_SHA256: [u8; 13] = hex!("060B6086480186FA6B50090103");
pub const DS_MLDSA65_RSA3072_PSS_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090105");
pub const DS_MLDSA65_RSA4096_PSS_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090106");
pub const DS_MLDSA65_RSA4096_PKCS15_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090107");
pub const DS_MLDSA65_ECDSA_P256_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090108");
pub const DS_MLDSA65_ECDSA_P384_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090109");
pub const DS_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512: [u8; 13] = hex!("060B6086480186FA6B5009010A");
pub const DS_MLDSA65_ED25519_SHA512: [u8; 13] = hex!("060B6086480186FA6B5009010B");
pub const DS_MLDSA87_ECDSA_P384_SHA512: [u8; 13] = hex!("060B6086480186FA6B5009010C");
pub const DS_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512: [u8; 13] = hex!("060B6086480186FA6B5009010D");
pub const DS_MLDSA87_ED448_SHAKE256: [u8; 13] = hex!("060B6086480186FA6B5009010E");
pub const DS_MLDSA87_RSA3072_PSS_SHA512: [u8; 13] = hex!("060B6086480186FA6B5009010F");
pub const DS_MLDSA87_RSA4096_PSS_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090110");
pub const DS_MLDSA87_ECDSA_P521_SHA512: [u8; 13] = hex!("060B6086480186FA6B50090111");


