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

use const_oid::ObjectIdentifier;

/// OID for the ML-DSA-44 parameter set as defined in [NIST CSOR].
/// ```text
/// id-ml-dsa-44 OBJECT IDENTIFIER ::= { sigAlgs 17 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// OID for the ML-DSA-65 parameter set as defined in [NIST CSOR].
/// ```text
/// id-ml-dsa-65 OBJECT IDENTIFIER ::= { sigAlgs 18}
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// OID for the ML-DSA-87 parameter set as defined in [NIST CSOR].
/// ```text
/// id-ml-dsa-87 OBJECT IDENTIFIER ::= { sigAlgs 19}
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// OID for the SLH-DSA-SHA2-128s parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-sha2-128s OBJECT IDENTIFIER ::= { sigAlgs 20 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHA2_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.20");

/// OID for the SLH-DSA-SHA2-128f parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-sha2-128f OBJECT IDENTIFIER ::= { sigAlgs 21 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHA2_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.21");

/// OID for the SLH-DSA-SHA2-192s parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-sha2-192s OBJECT IDENTIFIER ::= { sigAlgs 22 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHA2_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.22");

/// OID for the SLH-DSA-SHA2-192f parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-sha2-192f OBJECT IDENTIFIER ::= { sigAlgs 23 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHA2_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.23");

/// OID for the SLH-DSA-SHA2-256s parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-sha2-256s OBJECT IDENTIFIER ::= { sigAlgs 24 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHA2_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24");

/// OID for the SLH-DSA-SHA2-256f parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-sha2-256f OBJECT IDENTIFIER ::= { sigAlgs 25 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHA2_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.25");

/// OID for the SLH-DSA-SHAKE-128s parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-shake-128s OBJECT IDENTIFIER ::= { sigAlgs 26 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHAKE_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.26");

/// OID for the SLH-DSA-SHAKE-128f parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-shake-128f OBJECT IDENTIFIER ::= { sigAlgs 27 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHAKE_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.27");

/// OID for the SLH-DSA-SHAKE-192s parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-shake-192s OBJECT IDENTIFIER ::= { sigAlgs 28 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHAKE_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.28");

/// OID for the SLH-DSA-SHAKE-192f parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-shake-192f OBJECT IDENTIFIER ::= { sigAlgs 29 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHAKE_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.29");

/// OID for the SLH-DSA-SHAKE-256s parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-shake-256s OBJECT IDENTIFIER ::= { sigAlgs 30 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHAKE_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.30");

/// OID for the SLH-DSA-SHAKE-256f parameter set as defined in [NIST CSOR].
/// ```text
/// id-slh-dsa-shake-256f OBJECT IDENTIFIER ::= { sigAlgs 31 }
/// ```
/// [NIST CSOR]: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
pub const SLH_DSA_SHAKE_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.31");

// HACKATHON OIDs (NON-STANDARD - DO NOT USE)
/// ML_DSA_44_IPD    1.3.6.1.4.1.2.267.12.4.4
pub const ML_DSA_44_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.4.4");

/// ML_DSA_65_IPD    1.3.6.1.4.1.2.267.12.6.5*
pub const ML_DSA_65_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.6.5");

/// ML_DSA_87_IPD    1.3.6.1.4.1.2.267.12.8.7*
pub const ML_DSA_87_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.12.8.7");

/// Falcon-512                    1.3.9999.3.6*
pub const OQ_FALCON_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.6");

/// Falcon-1024                    1.3.9999.3.9*
pub const OQ_FALCON_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.9");

/// SLH_DSA_SHA2_128F_IPD    1.3.9999.6.4.13*
pub const SLH_DSA_SHA2_128F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.13");

/// SLH_DSA_SHA2_128S_IPD        1.3.9999.6.4.16*
pub const SLH_DSA_SHA2_128S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.4.16");

/// SLH_DSA_SHA2_192F_IPD    1.3.9999.6.5.10*
pub const SLH_DSA_SHA2_192F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.5.10");

/// SLH_DSA_SHA2_192S_IPD    1.3.9999.6.5.12*
pub const SLH_DSA_SHA2_192S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.5.12");

/// SLH_DSA_SHA2_256F_IPD        1.3.9999.6.6.10*
pub const SLH_DSA_SHA2_256F_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.6.10");

/// SLH_DSA_SHA2_256S_IPD        1.3.9999.6.6.12*
pub const SLH_DSA_SHA2_256S_IPD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.6.6.12");

/// SLH_DSA_SHAKE_128F_IPD    1.3.9999.6.7.13*
pub const SLH_DSA_SHAKE_128F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.7.13");

/// SLH_DSA_SHAKE_128S_IPD        1.3.9999.6.7.16*
pub const SLH_DSA_SHAKE_128S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.7.16");

/// SLH_DSA_SHAKE_192F_IPD    1.3.9999.6.8.10*
pub const SLH_DSA_SHAKE_192F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.8.10");

/// SLH_DSA_SHAKE_192S_IPD    1.3.9999.6.8.12*
pub const SLH_DSA_SHAKE_192S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.8.12");

/// SLH_DSA_SHAKE_256F_IPD        1.3.9999.6.9.10*
pub const SLH_DSA_SHAKE_256F_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.9.10");

/// SLH_DSA_SHAKE_256S_IPD        1.3.9999.6.9.12*
pub const SLH_DSA_SHAKE_256S_IPD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.9.12");

// Old Composite OIDs
/// COMPOSITE-Signature            1.3.6.1.4.1.18227.2.1
pub const ENTU_COMPOSITE_SIG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.18227.2.1");

/// COMPOSITE-KEY                2.16.840.1.114027.80.4.1
pub const ENTU_COMPOSITE_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.4.1");

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
