//! Composite key-related types as defined in draft-ounsworth-pq-composite-keys-03 and draft-ounsworth-pq-composite-sigs-07

use crate::oak::OneAsymmetricKey;
use alloc::vec::Vec;
use der::asn1::{BitString, OctetString};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// CompositePublicKey ::= SEQUENCE SIZE (2..MAX) OF SubjectPublicKeyInfo
pub type CompositePublicKey = Vec<SubjectPublicKeyInfoOwned>;

/// CompositePublicKeyOs ::= OCTET STRING (CONTAINING CompositePublicKey ENCODED BY der)
pub type CompositePublicKeyOs = OctetString;

/// CompositePublicKeyBs ::= BIT STRING (CONTAINING CompositePublicKey ENCODED BY der)
pub type CompositePublicKeyBs = BitString;

/// CompositePrivateKey ::= SEQUENCE SIZE (2..MAX) OF OneAsymmetricKey
pub type CompositePrivateKey = Vec<OneAsymmetricKey>;

/// CompositeParams ::= SEQUENCE SIZE (2..MAX) OF AlgorithmIdentifier
pub type CompositeParams = Vec<AlgorithmIdentifierOwned>;

/// CompositeSignatureValue ::= SEQUENCE SIZE (2..MAX) OF BIT STRING
pub type CompositeSignatureValue = Vec<BitString>;
