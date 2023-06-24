//! OIDs for PQC algorithms

use const_oid::ObjectIdentifier;

/// OPEN Quantum SAFE TEST OID LIST
/// Algorithm Name	            OID	                        Signature Algorithm
/// RSA	                        1.2.840.113549.1.1.1	    SHA256withRSA, SHA384withRSA, SHA512withRSA
pub const OQ_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// ECDSA	                    1.2.840.10045.2.1	        SHA256withEC, SHA384withEC, SHA512withEC
pub const OQ_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Dilithium2	                1.3.6.1.4.1.2.267.7.4.4*	Dilithium2
pub const OQ_DILITHIUM2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.4.4");
/// Dilithium3	                1.3.6.1.4.1.2.267.7.6.5*	Dilithium3
pub const OQ_DILITHIUM3: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.6.5");
/// Dilithium5	                1.3.6.1.4.1.2.267.7.8.7*	Dilithium5
pub const OQ_DILITHIUM5: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.7.8.7");
/// DilithiumAES2	            1.3.6.1.4.1.2.267.11.4.4*	Dilithium2-AES
pub const OQ_DILITHIUM_AES2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.11.4.4");
/// DilithiumAES3	            1.3.6.1.4.1.2.267.11.6.5*	Dilithium3-AES
pub const OQ_DILITHIUM_AES3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.11.6.5");
/// DilithiumAES5	            1.3.6.1.4.1.2.267.11.8.7*	Dilithium5-AES
pub const OQ_DILITHIUM_AES5: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.2.267.11.8.7");

/// Falcon-512	                1.3.9999.3.1*	            Falcon-512
pub const OQ_FALCON_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.1");
/// Falcon-1024	                1.3.9999.3.4*	            Falcon-1024
pub const OQ_FALCON_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.3.4");

/// SPHINCS+-SHA256-128f-robust	1.3.9999.6.4.1*	            SPHINCS+-SHA256-128f-robust
pub const OQ_SPHINCSP_SHA256_128F_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.4.1");
/// SPHINCS+-SHA256-128f-simple	1.3.9999.6.4.4*	            SPHINCS+-SHA256-128f-simple
pub const OQ_SPHINCSP_SHA256_128F_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.4.4");
/// SPHINCS+-SHA256-128s-robust	1.3.9999.6.4.7*	            SPHINCS+-SHA256-128s-robust
pub const OQ_SPHINCSP_SHA256_128S_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.4.7");
/// SPHINCS+-SHA256-128s-simple	1.3.9999.6.4.10*	        SPHINCS+-SHA256-128s-simple
pub const OQ_SPHINCSP_SHA256_128S_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.4.10");
/// SPHINCS+-SHA256-192f-robust	1.3.9999.6.5.1*	            SPHINCS+-SHA256-192f-robust
pub const OQ_SPHINCSP_SHA256_192F_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.5.1");
/// SPHINCS+-SHA256-192f-simple	1.3.9999.6.5.3*	            SPHINCS+-SHA256-192f-simple
pub const OQ_SPHINCSP_SHA256_192F_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.5.3");
/// SPHINCS+-SHA256-192s-robust	1.3.9999.6.5.5	            SPHINCS+-SHA256-192s-robust
pub const OQ_SPHINCSP_SHA256_192S_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.5.5");
/// SPHINCS+-SHA256-192s-simple	1.3.9999.6.5.7*	            SPHINCS+-SHA256-192s-simple
pub const OQ_SPHINCSP_SHA256_192S_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.5.7");
/// SPHINCS+-SHA256-256f-robust	1.3.9999.6.6.1*	            SPHINCS+-SHA256-256f-robust
pub const OQ_SPHINCSP_SHA256_256F_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.6.1");
/// SPHINCS+-SHA256-256f-simple	1.3.9999.6.6.3*	            SPHINCS+-SHA256-256f-simple
pub const OQ_SPHINCSP_SHA256_256F_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.6.3");
/// SPHINCS+-SHA256-256s-robust	1.3.9999.6.6.5*	            SPHINCS+-SHA256-256s-robust
pub const OQ_SPHINCSP_SHA256_256S_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.6.5");
/// SPHINCS+-SHA256-256s-simple	1.3.9999.6.6.7*	            SPHINCS+-SHA256-256s-simple
pub const OQ_SPHINCSP_SHA256_256S_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.9999.6.6.7");

/// Entrust Test OID List
/// Algorithm Name	            OID	                            Signature Algorithm
/// RSA	                        1.2.840.113549.1.1.1	        SHA256withRSA, SHA384withRSA, SHA512withRSA
pub const ENTU_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// ECDSA	                    1.2.840.10045.2.1	            SHA256withEC, SHA384withEC, SHA512withEC
pub const ENTU_ECDSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// COMPOSITE-Signature	        1.3.6.1.4.1.18227.2.1	        COMPOSITE-Signature
pub const ENTU_COMPOSITE_SIG: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.18227.2.1");
/// COMPOSITE-KEY	            2.16.840.1.114027.80.4.1	    COMPOSITE-KEY
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

/// Dilithium2	                2.16.840.1.114027.80.3.2.1*     Dilithium2
pub const ENTU_DILITHIUM2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.2.1");
/// Dilithium3	                2.16.840.1.114027.80.3.2.2*     Dilithium3
pub const ENTU_DILITHIUM3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.2.2");
/// Dilithium5	                2.16.840.1.114027.80.3.2.3*     Dilithium5
pub const ENTU_DILITHIUM5: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.2.3");
/// DilithiumAES2	            2.16.840.1.114027.80.3.2.4*     Dilithium2-AES
pub const ENTU_DILITHIUM_AES2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.2.4");
/// DilithiumAES3	            2.16.840.1.114027.80.3.2.5*     Dilithium3-AES
pub const ENTU_DILITHIUM_AES3: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.2.5");
/// DilithiumAES5	            2.16.840.1.114027.80.3.2.6*     Dilithium5-AES
pub const ENTU_DILITHIUM_AES5: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.2.6");

/// Falcon-512	                2.16.840.1.114027.80.3.3.1*     Falcon-512
pub const ENTU_FALCON_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.3.1");
/// Falcon-1024	                2.16.840.1.114027.80.3.3.2*     Falcon-1024
pub const ENTU_FALCON_1024: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.3.2");

/// SPHINCS+-SHA256-128f-robust	2.16.840.1.114027.80.3.4.1*     SPHINCS+-SHA256-128f-robust
pub const ENTU_SPHINCSP_SHA256_128F_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.1");
/// SPHINCS+-SHA256-128f-simple	2.16.840.1.114027.80.3.4.2*     SPHINCS+-SHA256-128f-simple
pub const ENTU_SPHINCSP_SHA256_128F_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.2");
/// SPHINCS+-SHA256-128s-robust	2.16.840.1.114027.80.3.4.3*     SPHINCS+-SHA256-128s-robust
pub const ENTU_SPHINCSP_SHA256_128S_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.3");
/// SPHINCS+-SHA256-128s-simple	2.16.840.1.114027.80.3.4.4*     SPHINCS+-SHA256-128s-simple
pub const ENTU_SPHINCSP_SHA256_128S_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.4");
/// SPHINCS+-SHA256-192f-robust	2.16.840.1.114027.80.3.4.5*     SPHINCS+-SHA256-192f-robust
pub const ENTU_SPHINCSP_SHA256_192F_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.5");
/// SPHINCS+-SHA256-192f-simple	2.16.840.1.114027.80.3.4.6*     SPHINCS+-SHA256-192f-simple
pub const ENTU_SPHINCSP_SHA256_192F_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.6");
/// SPHINCS+-SHA256-192s-robust	2.16.840.1.114027.80.3.4.7*     SPHINCS+-SHA256-192s-robust
pub const ENTU_SPHINCSP_SHA256_192S_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.7");
/// SPHINCS+-SHA256-192s-simple	2.16.840.1.114027.80.3.4.8*     SPHINCS+-SHA256-192s-simple
pub const ENTU_SPHINCSP_SHA256_192S_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.8");
/// SPHINCS+-SHA256-256f-robust	2.16.840.1.114027.80.3.4.9*	    SPHINCS+-SHA256-256f-robust
pub const ENTU_SPHINCSP_SHA256_256F_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.9");
/// SPHINCS+-SHA256-256f-simple	2.16.840.1.114027.80.3.4.10*	SPHINCS+-SHA256-256f-simple
pub const ENTU_SPHINCSP_SHA256_256F_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.10");
/// SPHINCS+-SHA256-256s-robust	2.16.840.1.114027.80.3.4.11*	SPHINCS+-SHA256-256s-robust
pub const ENTU_SPHINCSP_SHA256_256S_ROBUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.11");
/// SPHINCS+-SHA256-256s-simple	2.16.840.1.114027.80.3.4.12*	SPHINCS+-SHA256-256s-simple
pub const ENTU_SPHINCSP_SHA256_256S_SIMPLE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.3.4.12");
