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
pub const ID_MLKEM1024_RSA3072_HMAC_SHA512: ObjectIdentifier =
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
pub const DS_MLKEM768_ECDH_BRAINPOOL_P256R1_HMAC_SHA256: [u8; 13] =
    hex!("060B6086480186FA6B50050238");
pub const DS_MLKEM1024_RSA3072_HMAC_SHA512: [u8; 13] = hex!("060B6086480186FA6B5005023D");
pub const DS_MLKEM1024_ECDH_P384_HMAC_SHA512: [u8; 13] = hex!("060B6086480186FA6B50050239");
pub const DS_MLKEM1024_ECDH_BRAINPOOL_P384R1_HMAC_SHA512: [u8; 13] =
    hex!("060B6086480186FA6B5005023A");
pub const DS_MLKEM1024_X448_SHA3_256: [u8; 13] = hex!("060B6086480186FA6B5005023B");
pub const DS_MLKEM1024_ECDH_P521_HMAC_SHA512: [u8; 13] = hex!("060B6086480186FA6B5005023C");

pub const ID_MLDSA44_RSA2048_PSS_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.20");
pub const ID_MLDSA44_RSA2048_PKCS15_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.21");
pub const ID_MLDSA44_ED25519_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.22");
pub const ID_MLDSA44_ECDSA_P256_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.23");
pub const ID_MLDSA65_RSA3072_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.24");
pub const ID_MLDSA65_RSA3072_PKCS15_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.25");
pub const ID_MLDSA65_RSA4096_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.26");
pub const ID_MLDSA65_RSA4096_PKCS15_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.27");
pub const ID_MLDSA65_ECDSA_P256_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.28");
pub const ID_MLDSA65_ECDSA_P384_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.29");
pub const ID_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.30");
pub const ID_MLDSA65_ED25519_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.31");
pub const ID_MLDSA87_ECDSA_P384_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.32");
pub const ID_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.33");
pub const ID_MLDSA87_ED448_SHAKE256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.34");
pub const ID_MLDSA87_RSA3072_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.35");
pub const ID_MLDSA87_RSA4096_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.36");
pub const ID_MLDSA87_ECDSA_P521_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.9.1.37");

pub const DS_MLDSA44_RSA2048_PSS_SHA256: &[u8; 34] = b"COMPSIG-MLDSA44-RSA2048-PSS-SHA256";
pub const DS_MLDSA44_RSA2048_PKCS15_SHA256: &[u8; 37] = b"COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256";
pub const DS_MLDSA44_ED25519_SHA512: &[u8; 30] = b"COMPSIG-MLDSA44-Ed25519-SHA512";
pub const DS_MLDSA44_ECDSA_P256_SHA256: &[u8; 33] = b"COMPSIG-MLDSA44-ECDSA-P256-SHA256";
pub const DS_MLDSA65_RSA3072_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA65-RSA3072-PSS-SHA512";
pub const DS_MLDSA65_RSA3072_PKCS15_SHA512: &[u8; 37] = b"COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512";
pub const DS_MLDSA65_RSA4096_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA65-RSA4096-PSS-SHA512";
pub const DS_MLDSA65_RSA4096_PKCS15_SHA512: &[u8; 37] = b"COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512";
pub const DS_MLDSA65_ECDSA_P256_SHA512: &[u8; 27] = b"COMPSIG-MLDSA65-P256-SHA512";
pub const DS_MLDSA65_ECDSA_P384_SHA512: &[u8; 27] = b"COMPSIG-MLDSA65-P384-SHA512";
pub const DS_MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512: &[u8; 28] = b"COMPSIG-MLDSA65-BP256-SHA512";
pub const DS_MLDSA65_ED25519_SHA512: &[u8; 30] = b"COMPSIG-MLDSA65-Ed25519-SHA512";
pub const DS_MLDSA87_ECDSA_P384_SHA512: &[u8; 27] = b"COMPSIG-MLDSA87-P384-SHA512";
pub const DS_MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512: &[u8; 28] = b"COMPSIG-MLDSA87-BP384-SHA512";
pub const DS_MLDSA87_ED448_SHAKE256: &[u8; 30] = b"COMPSIG-MLDSA87-Ed448-SHAKE256";
pub const DS_MLDSA87_RSA3072_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA87-RSA3072-PSS-SHA512";
pub const DS_MLDSA87_RSA4096_PSS_SHA512: &[u8; 34] = b"COMPSIG-MLDSA87-RSA4096-PSS-SHA512";
pub const DS_MLDSA87_ECDSA_P521_SHA512: &[u8; 27] = b"COMPSIG-MLDSA87-P521-SHA512";

