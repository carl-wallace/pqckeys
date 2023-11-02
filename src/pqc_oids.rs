//! OIDs for PQC algorithms as captured here: https://github.com/IETF-Hackathon/pqc-certificates/blob/master/docs/oid_mapping.md

use const_oid::ObjectIdentifier;

/// ML_DSA_44_IPD    1.3.6.1.4.1.2.267.12.4.4    ML_DSA_44_IPD
pub const ML_DSA_44_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.4.4");

/// ML_DSA_65_IPD    1.3.6.1.4.1.2.267.12.6.5*    ML_DSA_65_IPD
pub const ML_DSA_65_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.6.5");

/// ML_DSA_87_IPD    1.3.6.1.4.1.2.267.12.8.7*    ML_DSA_87_IPD
pub const ML_DSA_87_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.8.7");

/// Falcon-512                    1.3.9999.3.6*                Falcon-512
pub const OQ_FALCON_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.6");

/// Falcon-1024                    1.3.9999.3.9*                Falcon-1024
pub const OQ_FALCON_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.9");

/// SLH_DSA_SHA2_128F_IPD    1.3.9999.6.4.13*                SLH_DSA_SHA2_128F_IPD
pub const SLH_DSA_SHA2_128F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.13");

/// SLH_DSA_SHA2_128S_IPD        1.3.9999.6.4.16*            SLH_DSA_SHA2_128S_IPD
pub const SLH_DSA_SHA2_128S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.16");

/// SLH_DSA_SHA2_192F_IPD    1.3.9999.6.5.10*                SLH_DSA_SHA2_192F_IPD
pub const SLH_DSA_SHA2_192F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.5.10");

/// SLH_DSA_SHA2_192S_IPD    1.3.9999.6.5.12*                SLH_DSA_SHA2_192S_IPD
pub const SLH_DSA_SHA2_192S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.5.12");

/// SLH_DSA_SHA2_256F_IPD        1.3.9999.6.6.10*            SLH_DSA_SHA2_256F_IPD
pub const SLH_DSA_SHA2_256F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.6.10");

/// SLH_DSA_SHA2_256S_IPD        1.3.9999.6.6.12*           SLH_DSA_SHA2_256S_IPD
pub const SLH_DSA_SHA2_256S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.6.12");

/// SLH_DSA_SHAKE_128F_IPD    1.3.9999.6.7.13*                SLH_DSA_SHAKE_128F_IPD
pub const SLH_DSA_SHAKE_128F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.7.13");

/// SLH_DSA_SHAKE_128S_IPD        1.3.9999.6.7.16*            SLH_DSA_SHAKE_128S_IPD
pub const SLH_DSA_SHAKE_128S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.7.16");

/// SLH_DSA_SHAKE_192F_IPD    1.3.9999.6.8.10*                SLH_DSA_SHAKE_192F_IPD
pub const SLH_DSA_SHAKE_192F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.8.10");

/// SLH_DSA_SHAKE_192S_IPD    1.3.9999.6.8.12*                SLH_DSA_SHAKE_192S_IPD
pub const SLH_DSA_SHAKE_192S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.8.12");

/// SLH_DSA_SHAKE_256F_IPD        1.3.9999.6.9.10*            SLH_DSA_SHAKE_256F_IPD
pub const SLH_DSA_SHAKE_256F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.9.10");

/// SLH_DSA_SHAKE_256S_IPD        1.3.9999.6.9.12*           SLH_DSA_SHAKE_256S_IPD
pub const SLH_DSA_SHAKE_256S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.9.12");

// Old Composite OIDs
/// COMPOSITE-Signature            1.3.6.1.4.1.18227.2.1            COMPOSITE-Signature
pub const ENTU_COMPOSITE_SIG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.18227.2.1");

/// COMPOSITE-KEY                2.16.840.1.114027.80.4.1        COMPOSITE-KEY
pub const ENTU_COMPOSITE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.4.1");

///    id-composite-key OBJECT IDENTIFIER ::= {
///        joint-iso-itu-t(2) country(16) us(840) organization(1) entrust(114027)
///        Algorithm(80) Composite(4) CompositeKey(1) }
pub const ENTU_COMPOSITE_KEY_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.4.1");

///    id-Dilithium3-ECDSA-P256 OBJECT IDENTIFIER ::= {
///      joint-iso-itu-t(2) country(16) us(840) organization(1) entrust(114027)
///      algorithm(80) ExplicitCompositeKey(5) id-Dilithium3-ECDSA-P256(1) }
pub const ENTU_DILITHIUM3_ECDSA_P256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.1");

///    id-Dilithium3-RSA OBJECT IDENTIFIER ::= {
///      joint-iso-itu-t(2) country(16) us(840) organization(1) entrust(114027)
///      algorithm(80) ExplicitCompositeKey(5) id-Dilithium3-RSA(2) }
pub const ENTU_DILITHIUM3_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.5.2");
