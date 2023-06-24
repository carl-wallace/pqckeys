//! OneAsymmetricKey and related types as defined in RFC 5958

use alloc::vec::Vec;
use der::asn1::{BitString, OctetString};
use der::{Enumerated, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;

///   AsymmetricKeyPackage ::= SEQUENCE SIZE (1..MAX) OF OneAsymmetricKey
pub type AsymmetricKeyPackage = Vec<OneAsymmetricKey>;

///    OneAsymmetricKey ::= SEQUENCE {
///      version                   Version,
///      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///      privateKey                PrivateKey,
///      attributes            [0] Attributes OPTIONAL,
///      ...,
///      [[2: publicKey        [1] PublicKey OPTIONAL ]],
///      ...
///    }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OneAsymmetricKey {
    pub version: Version,
    pub private_key_alg: PrivateKeyAlgorithmIdentifier,
    pub private_key: PrivateKey,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub attributes: Option<Attributes>,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub public_key: Option<PublicKey>,
}

///    PrivateKeyInfo ::= OneAsymmetricKey
pub type PrivateKeyInfo = OneAsymmetricKey;

///   -- PrivateKeyInfo is used by [P12]. If any items tagged as version
///    -- 2 are used, the version must be v2, else the version should be
///    -- v1. When v1, PrivateKeyInfo is the same as it was in [RFC5208].
///
///    Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Version {
    V1 = 0,
    V2 = 1,
}

///   PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
///                                       { PUBLIC-KEY,
///                                         { PrivateKeyAlgorithms } }
pub type PrivateKeyAlgorithmIdentifier = AlgorithmIdentifierOwned;

///    PrivateKey ::= OCTET STRING
///                      -- Content varies based on type of key. The
///                      -- algorithm identifier dictates the format of
///                      -- the key.
pub type PrivateKey = OctetString;

///
///    PublicKey ::= BIT STRING
///                      -- Content varies based on type of key. The
///                      -- algorithm identifier dictates the format of
///                      -- the key.
pub type PublicKey = BitString;

///   EncryptedPrivateKeyInfo ::= SEQUENCE {
///      encryptionAlgorithm  EncryptionAlgorithmIdentifier,
///      encryptedData        EncryptedData }
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptedPrivateKeyInfo {
    pub enc_alg: EncryptionAlgorithmIdentifier,
    pub enc_data: EncryptedData,
}

///    EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
///                                        { CONTENT-ENCRYPTION,
///                                          { KeyEncryptionAlgorithms } }
pub type EncryptionAlgorithmIdentifier = AlgorithmIdentifierOwned;

///    EncryptedData ::= OCTET STRING -- Encrypted PrivateKeyInfo
pub type EncryptedData = OctetString;
