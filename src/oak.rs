//! OneAsymmetricKey and related types as defined in [RFC 5958](https://datatracker.ietf.org/doc/html/rfc5958)

use alloc::vec::Vec;
use der::asn1::{BitString, OctetString};
use der::{Enumerated, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;

/// AsymmetricKeyPackage as defined in [RFC 5958 Section 2].
/// ```text
/// AsymmetricKeyPackage ::= SEQUENCE SIZE (1..MAX) OF OneAsymmetricKey
/// ```
/// [RFC 5958 Section 2]: https://datatracker.ietf.org/doc/html/rfc5958#section-2
pub type AsymmetricKeyPackage = Vec<OneAsymmetricKey>;

/// OneAsymmetricKey as defined in [RFC 5958 Section 2].
/// ```text
/// OneAsymmetricKey ::= SEQUENCE {
///   version                   Version,
///   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
///   privateKey                PrivateKey,
///   attributes            [0] Attributes OPTIONAL,
///   ...,
///   [[2: publicKey        [1] PublicKey OPTIONAL ]],
///   ...
/// }
/// ```
/// [RFC 5958 Section 2]: https://datatracker.ietf.org/doc/html/rfc5958#section-2
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

/// PrivateKeyInfo as defined in [RFC 5958 Section 2].
/// ```text
/// PrivateKeyInfo ::= OneAsymmetricKey
/// ```
/// [RFC 5958 Section 2]: https://datatracker.ietf.org/doc/html/rfc5958#section-2
pub type PrivateKeyInfo = OneAsymmetricKey;

/// Version as defined in [RFC 5958 Section 2].
/// ```text
/// Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)
/// ```
/// [RFC 5958 Section 2]: https://datatracker.ietf.org/doc/html/rfc5958#section-2
#[derive(Clone, Debug, Copy, PartialEq, Eq, PartialOrd, Ord, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
#[allow(missing_docs)]
pub enum Version {
    V1 = 0,
    V2 = 1,
}

/// PrivateKeyAlgorithmIdentifier as defined in [RFC 5958 Section 2].
/// ```text
/// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
///                                     { PUBLIC-KEY, { PrivateKeyAlgorithms } }
/// ```
/// [RFC 5958 Section 2]: https://datatracker.ietf.org/doc/html/rfc5958#section-2
pub type PrivateKeyAlgorithmIdentifier = AlgorithmIdentifierOwned;

/// PrivateKey as defined in [RFC 5958 Section 2].
/// ```text
/// PrivateKey ::= OCTET STRING
///                   -- Content varies based on type of key. The
///                   -- algorithm identifier dictates the format of
///                   -- the key.
/// ```
/// [RFC 5958 Section 2]: https://datatracker.ietf.org/doc/html/rfc5958#section-2
pub type PrivateKey = OctetString;

/// PublicKey as defined in [RFC 5958 Section 2].
/// ```text
/// PublicKey ::= BIT STRING
///                   -- Content varies based on type of key. The
///                   -- algorithm identifier dictates the format of
///                   -- the key.
/// ```
/// [RFC 5958 Section 2]: https://datatracker.ietf.org/doc/html/rfc5958#section-2
pub type PublicKey = BitString;

/// EncryptedPrivateKeyInfo as defined in [RFC 5958 Section 3].
/// ```text
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///    encryptionAlgorithm  EncryptionAlgorithmIdentifier,
///    encryptedData        EncryptedData }
/// ```
/// [RFC 5958 Section 3]: https://datatracker.ietf.org/doc/html/rfc5958#section-3
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncryptedPrivateKeyInfo {
    pub enc_alg: EncryptionAlgorithmIdentifier,
    pub enc_data: EncryptedData,
}

/// EncryptionAlgorithmIdentifier as defined in [RFC 5958 Section 3].
/// ```text
/// EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
///                                     { CONTENT-ENCRYPTION,
///                                       { KeyEncryptionAlgorithms } }
/// ```
/// [RFC 5958 Section 3]: https://datatracker.ietf.org/doc/html/rfc5958#section-3
pub type EncryptionAlgorithmIdentifier = AlgorithmIdentifierOwned;

/// EncryptedData as defined in [RFC 5958 Section 3].
/// ```text
/// EncryptedData ::= OCTET STRING -- Encrypted PrivateKeyInfo
/// ```
/// [RFC 5958 Section 3]: https://datatracker.ietf.org/doc/html/rfc5958#section-3
pub type EncryptedData = OctetString;
