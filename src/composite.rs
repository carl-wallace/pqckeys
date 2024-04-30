//! Composite signature-related types as defined in [draft-ounsworth-pq-composite-sigs-13](https://datatracker.ietf.org/doc/html/draft-ounsworth-pq-composite-sigs-13)

use crate::oak::OneAsymmetricKey;
use der::asn1::{BitString, OctetString};
use spki::SubjectPublicKeyInfoOwned;

/// CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
pub type CompositeSignaturePublicKey = [SubjectPublicKeyInfoOwned; 2];

/// CompositeSignaturePublicKeyOs ::= OCTET STRING (CONTAINING CompositeSignaturePublicKey ENCODED BY der)
pub type CompositeSignaturePublicKeyOs = OctetString;

/// CompositeSignaturePublicKeyBs ::= BIT STRING (CONTAINING CompositeSignaturePublicKey ENCODED BY der)
pub type CompositePublicKeyBs = BitString;

/// CompositeSignaturePrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
pub type CompositeSignaturePrivateKey = [OneAsymmetricKey; 2];

/// CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
pub type CompositeSignatureValue = [BitString; 2];
