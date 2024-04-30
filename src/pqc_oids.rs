//! OIDs for PQC algorithms as captured in the IETF PQC Certificate hackathon's [OID mapping](https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md)

use const_oid::ObjectIdentifier;

/// 1.3.6.1.4.1.2.267.12.4.4
pub const ML_DSA_44_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.4.4");

/// 1.3.6.1.4.1.2.267.12.6.5
pub const ML_DSA_65_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.6.5");

/// 1.3.6.1.4.1.2.267.12.8.7
pub const ML_DSA_87_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.8.7");

/// 1.3.9999.3.6
pub const FALCON_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.6");

/// 1.3.9999.3.9
pub const FALCON_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.9");

/// 1.3.9999.6.4.13
pub const SLH_DSA_SHA2_128F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.13");

/// 1.3.9999.6.4.16
pub const SLH_DSA_SHA2_128S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.16");

/// 1.3.9999.6.5.10
pub const SLH_DSA_SHA2_192F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.5.10");

/// 1.3.9999.6.5.12
pub const SLH_DSA_SHA2_192S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.5.12");

/// 1.3.9999.6.6.10
pub const SLH_DSA_SHA2_256F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.6.10");

/// 1.3.9999.6.6.12
pub const SLH_DSA_SHA2_256S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.6.12");

/// 1.3.9999.6.7.13
pub const SLH_DSA_SHAKE_128F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.7.13");

/// 1.3.9999.6.7.16
pub const SLH_DSA_SHAKE_128S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.7.16");

/// 1.3.9999.6.8.10
pub const SLH_DSA_SHAKE_192F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.8.10");

/// 1.3.9999.6.8.12
pub const SLH_DSA_SHAKE_192S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.8.12");

/// 1.3.9999.6.9.10
pub const SLH_DSA_SHAKE_256F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.9.10");

/// 1.3.9999.6.9.12
pub const SLH_DSA_SHAKE_256S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.9.12");

/// 1.3.6.1.4.1.22554.5.6.1
pub const ML_KEM_512_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.1");
/// 1.3.6.1.4.1.22554.5.6.2
pub const ML_KEM_768_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.2");
/// 1.3.6.1.4.1.22554.5.6.3
pub const ML_KEM_1024_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.22554.5.6.3");

/// 2.16.840.1.114027.80.8.1.1
pub const ML_DSA_44_RSA2048_PSS_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.1");

/// 2.16.840.1.114027.80.8.1.2
pub const ML_DSA_44_RSA2048_PKCS15_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.2");

/// 2.16.840.1.114027.80.8.1.3
pub const ML_DSA_44_ED25519_PKCS15_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.3");

/// 2.16.840.1.114027.80.8.1.4
pub const ML_DSA_44_ECDSA_P256_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.4");

/// 2.16.840.1.114027.80.8.1.5
pub const ML_DSA_44_ECDSA_BRAINPOOL_P256R1_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.5");

/// 2.16.840.1.114027.80.8.1.6
pub const ML_DSA_65_RSA3072_PSS_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.6");

/// 2.16.840.1.114027.80.8.1.7
pub const ML_DSA_65_RSA3072_PKCS15_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.7");

/// 2.16.840.1.114027.80.8.1.8
pub const ML_DSA_65_ECDSA_P256_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.8");

/// 2.16.840.1.114027.80.8.1.9
pub const ML_DSA_65_ECDSA_BRAINPOOL_P256R1_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.9");

/// 2.16.840.1.114027.80.8.1.10
pub const ML_DSA_65_ED25519_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.10");

/// 2.16.840.1.114027.80.8.1.11
pub const ML_DSA_87_ECDSA_P384_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.11");

/// 2.16.840.1.114027.80.8.1.12
pub const ML_DSA_87_ECDSA_BRAINPOOL_P384R1_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.12");

/// 2.16.840.1.114027.80.8.1.13
pub const ML_DSA_87_ED448_SHA512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.13");
