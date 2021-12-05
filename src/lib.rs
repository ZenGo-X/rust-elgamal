use serde::{Deserialize, Serialize};

pub mod dl_solvers;
pub mod elgamal;
pub mod prime;
pub mod rfc7919_groups;

pub use curv::arithmetic::BigInt;

pub struct ElGamal;
pub struct ExponentElGamal;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalPP {
    pub g: BigInt,
    pub q: BigInt,
    pub p: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalPublicKey {
    pub pp: ElGamalPP,
    pub h: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalPrivateKey {
    pub pp: ElGamalPP,
    pub x: BigInt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalKeyPair {
    pub pk: ElGamalPublicKey,
    pub sk: ElGamalPrivateKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    pub c1: BigInt,
    pub c2: BigInt,
    pub pp: ElGamalPP,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ElGamalError {
    EncryptionError,
    DecryptionError,
    HomomorphicError,
    ParamError,
}
