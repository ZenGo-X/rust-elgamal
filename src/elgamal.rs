use crate::prime::is_prime;
use crate::prime::is_safe_prime;
use crate::ElGamal;
use crate::ElGamalCiphertext;
use crate::ElGamalError;
use crate::ElGamalKeyPair;
use crate::ElGamalPP;
use crate::ElGamalPrivateKey;
use crate::ElGamalPublicKey;
use crate::ExponentElGamal;
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;

impl ElGamalPP {
    pub fn generate(bit_size: usize) -> Self {
        let mut p: BigInt;
        p = BigInt::sample(bit_size);
        while !is_prime(&p) {
            p = p + BigInt::one();
        }
        let g = BigInt::sample_below(&p);

        ElGamalPP { g, p }
    }

    pub fn generate_safe(bit_size: usize) -> Self {
        let mut p: BigInt;
        p = BigInt::sample(bit_size);
        while !is_safe_prime(&p) {
            p = BigInt::sample(bit_size);
        }
        let g = BigInt::sample_below(&p);

        ElGamalPP { g, p }
    }

    pub fn generate_from_predefined_randomness(
        g: &BigInt,
        p: &BigInt,
    ) -> Result<Self, ElGamalError> {
        //test 0<m<p
        if g.ge(&p) || g.le(&BigInt::zero()) {
            return Err(ElGamalError::ParamError);
        }
        if !is_prime(&p) {
            return Err(ElGamalError::ParamError);
        }
        Ok(ElGamalPP {
            g: g.clone(),
            p: p.clone(),
        })
    }
}

impl ElGamalKeyPair {
    pub fn generate(pp: &ElGamalPP) -> Self {
        let x = BigInt::sample_below(&pp.p);
        let h = BigInt::mod_pow(&pp.g, &x, &pp.p);
        let pk = ElGamalPublicKey { pp: pp.clone(), h };
        let sk = ElGamalPrivateKey { pp: pp.clone(), x };
        ElGamalKeyPair { pk, sk }
    }
}

impl ElGamal {
    pub fn encrypt(m: &BigInt, pk: &ElGamalPublicKey) -> Result<ElGamalCiphertext, ElGamalError> {
        //test 0<m<p
        if m.ge(&pk.pp.p) || m.le(&BigInt::zero()) {
            return Err(ElGamalError::EncryptionError);
        }
        let y = BigInt::sample_below(&pk.pp.p);
        let c1 = BigInt::mod_pow(&pk.pp.g, &y, &pk.pp.p);
        let s = BigInt::mod_pow(&pk.h, &y, &pk.pp.p);
        let c2 = BigInt::mod_mul(&s, &m, &pk.pp.p);
        Ok(ElGamalCiphertext {
            c1,
            c2,
            pp: pk.pp.clone(),
        })
    }

    pub fn encrypt_from_predefined_randomness(
        m: &BigInt,
        pk: &ElGamalPublicKey,
        randomness: &BigInt,
    ) -> Result<ElGamalCiphertext, ElGamalError> {
        //test 0<m<p
        if m.ge(&pk.pp.p) || m.le(&BigInt::zero()) {
            return Err(ElGamalError::EncryptionError);
        }
        let y = randomness;
        let c1 = BigInt::mod_pow(&pk.pp.g, y, &pk.pp.p);
        let s = BigInt::mod_pow(&pk.h, y, &pk.pp.p);
        let c2 = BigInt::mod_mul(&s, &m, &pk.pp.p);
        Ok(ElGamalCiphertext {
            c1,
            c2,
            pp: pk.pp.clone(),
        })
    }

    pub fn decrypt(c: &ElGamalCiphertext, sk: &ElGamalPrivateKey) -> Result<BigInt, ElGamalError> {
        if c.pp != sk.pp {
            return Err(ElGamalError::DecryptionError);
        }
        let c1_x = BigInt::mod_pow(&c.c1, &sk.x, &sk.pp.p);
        let c1_x_inv = BigInt::mod_inv(&c1_x, &sk.pp.p);
        Ok(BigInt::mod_mul(&c.c2, &c1_x_inv, &sk.pp.p))
    }

    //Enc(m1) mul Enc(m2) = Enc(m1m2)
    pub fn mul(
        c_a: &ElGamalCiphertext,
        c_b: &ElGamalCiphertext,
    ) -> Result<ElGamalCiphertext, ElGamalError> {
        if c_a.pp != c_b.pp {
            return Err(ElGamalError::HomomorphicError);
        }
        Ok(ElGamalCiphertext {
            c1: BigInt::mod_mul(&c_a.c1, &c_b.c1, &c_a.pp.p),
            c2: BigInt::mod_mul(&c_a.c2, &c_b.c2, &c_a.pp.p),
            pp: c_a.pp.clone(),
        })
    }

    pub fn pow(c: &ElGamalCiphertext, constant: &BigInt) -> ElGamalCiphertext {
        ElGamalCiphertext {
            c1: BigInt::mod_pow(&c.c1, &constant, &c.pp.p),
            c2: BigInt::mod_pow(&c.c2, &constant, &c.pp.p),
            pp: c.pp.clone(),
        }
    }
}

impl ExponentElGamal {
    pub fn encrypt(m: &BigInt, pk: &ElGamalPublicKey) -> Result<ElGamalCiphertext, ElGamalError> {
        // test 0<m<p
        // If decryption is required, a tighter bound is needed, i.e m < 2^32
        if m.ge(&pk.pp.p) || m.le(&BigInt::zero()) {
            return Err(ElGamalError::EncryptionError);
        }
        let g_m = BigInt::mod_mul(&pk.pp.g, m, &pk.pp.p);
        let y = BigInt::sample_below(&pk.pp.p);
        let c1 = BigInt::mod_pow(&pk.pp.g, &y, &pk.pp.p);
        let s = BigInt::mod_pow(&pk.h, &y, &pk.pp.p);
        let c2 = BigInt::mod_mul(&s, &g_m, &pk.pp.p);
        Ok(ElGamalCiphertext {
            c1,
            c2,
            pp: pk.pp.clone(),
        })
    }

    pub fn encrypt_from_predefined_randomness(
        m: &BigInt,
        pk: &ElGamalPublicKey,
        randomness: &BigInt,
    ) -> Result<ElGamalCiphertext, ElGamalError> {
        // test 0<m<p
        // If decryption is required, a tighter bound is needed, i.e m < 2^32
        if m.ge(&pk.pp.p) || m.le(&BigInt::zero()) {
            return Err(ElGamalError::EncryptionError);
        }
        let g_m = BigInt::mod_mul(&pk.pp.g, m, &pk.pp.p);
        let y = randomness;
        let c1 = BigInt::mod_pow(&pk.pp.g, y, &pk.pp.p);
        let s = BigInt::mod_pow(&pk.h, y, &pk.pp.p);
        let c2 = BigInt::mod_mul(&s, &g_m, &pk.pp.p);
        Ok(ElGamalCiphertext {
            c1,
            c2,
            pp: pk.pp.clone(),
        })
    }

    // returns g^m
    pub fn decrypt_exp(
        c: &ElGamalCiphertext,
        sk: &ElGamalPrivateKey,
    ) -> Result<BigInt, ElGamalError> {
        if c.pp != sk.pp {
            return Err(ElGamalError::DecryptionError);
        }
        let c1_x = BigInt::mod_pow(&c.c1, &sk.x, &sk.pp.p);
        let c1_x_inv = BigInt::mod_inv(&c1_x, &sk.pp.p);
        Ok(BigInt::mod_mul(&c.c2, &c1_x_inv, &sk.pp.p))
    }

    //returns m
    pub fn decrypt(
        _c: &ElGamalCiphertext,
        _sk: &ElGamalPrivateKey,
    ) -> Result<BigInt, ElGamalError> {
        //TODO
        return Err(ElGamalError::DecryptionError);
    }

    //Enc(g^m1) mul Enc(g^m2) = Enc(g^(m1+m2))
    pub fn add(
        c_a: &ElGamalCiphertext,
        c_b: &ElGamalCiphertext,
    ) -> Result<ElGamalCiphertext, ElGamalError> {
        if c_a.pp != c_b.pp {
            return Err(ElGamalError::HomomorphicError);
        }
        Ok(ElGamalCiphertext {
            c1: BigInt::mod_mul(&c_a.c1, &c_b.c1, &c_a.pp.p),
            c2: BigInt::mod_mul(&c_a.c2, &c_b.c2, &c_a.pp.p),
            pp: c_a.pp.clone(),
        })
    }

    // homomorphically multiply m by a known constant
    pub fn mul(c: &ElGamalCiphertext, constant: &BigInt) -> ElGamalCiphertext {
        ElGamalCiphertext {
            c1: BigInt::mod_pow(&c.c1, &constant, &c.pp.p),
            c2: BigInt::mod_pow(&c.c2, &constant, &c.pp.p),
            pp: c.pp.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ElGamal;
    use crate::ElGamalKeyPair;
    use crate::ElGamalPP;
    use curv::BigInt;

    #[test]
    fn test_elgamal() {
        let bit_size = 1024;
        let pp = ElGamalPP::generate(bit_size);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(13);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
        assert_eq!(message, message_tag);
    }

    #[test]
    fn test_elgamal_safe() {
        let bit_size = 1024;
        let pp = ElGamalPP::generate_safe(bit_size);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(13);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
        assert_eq!(message, message_tag);
    }

    #[test]
    fn test_mul() {
        let bit_size = 1024;
        let pp = ElGamalPP::generate(bit_size);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message1 = BigInt::from(13);
        let c1 = ElGamal::encrypt(&message1, &keypair.pk).unwrap();
        let message2 = BigInt::from(9);
        let c2 = ElGamal::encrypt(&message2, &keypair.pk).unwrap();
        let c = ElGamal::mul(&c1, &c2).unwrap();
        let message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
        assert_eq!(BigInt::from(117), message_tag);
    }

    #[test]
    fn test_pow() {
        let bit_size = 1024;
        let pp = ElGamalPP::generate(bit_size);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(13);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let constant = BigInt::from(3);
        let c_tag = ElGamal::pow(&c, &constant);
        let message_tag = ElGamal::decrypt(&c_tag, &keypair.sk).unwrap();
        assert_eq!(BigInt::from(2197), message_tag);
    }
}
