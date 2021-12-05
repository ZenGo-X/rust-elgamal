use curv::arithmetic::traits::Modulo;
use curv::arithmetic::One;
use curv::arithmetic::Zero;
use curv::BigInt;

// see https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm_for_logarithms#:~:text=Pollard's%20rho%20algorithm%20for%20logarithms%20is%20an%20algorithm%20introduced%20by,solve%20the%20integer%20factorization%20problem.&text=of%20the%20equation-,.,using%20the%20Extended%20Euclidean%20algorithm

const POLLARD_PARTITION_N: u32 = 3;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SolverError {
    PollardConvergenceError,
}

pub struct SimplePollard<'a> {
    p: &'a BigInt,     // prime
    big_p: &'a BigInt, // prime + 1
    alpha: &'a BigInt, // generator
    beta: &'a BigInt,  // m
}

impl<'a> SimplePollard<'a> {
    pub fn new(p: &'a BigInt, big_p: &'a BigInt, alpha: &'a BigInt, beta: &'a BigInt) -> Self {
        SimplePollard {
            p,
            big_p,
            alpha,
            beta,
        }
    }

    fn step(&self, x: &mut BigInt, a: &mut BigInt, b: &mut BigInt) {
        let step_interval = x.modulus(&BigInt::from(POLLARD_PARTITION_N));
        if step_interval == BigInt::zero() {
            *x = BigInt::mod_mul(x, x, &self.big_p);
            *a = BigInt::mod_mul(a, &BigInt::from(2), &self.p);
            *b = BigInt::mod_mul(b, &BigInt::from(2), &self.p);
        } else if step_interval == BigInt::one() {
            *x = BigInt::mod_mul(x, &self.alpha, &self.big_p);
            *a = BigInt::mod_add(a, &BigInt::one(), &self.big_p);
        } else {
            *x = BigInt::mod_mul(x, &self.beta, &self.big_p);
            *b = BigInt::mod_add(b, &BigInt::one(), &self.p);
        }
    }

    pub fn run(&self) -> Result<BigInt, SolverError> {
        let mut x = BigInt::one();
        let mut a = BigInt::zero();
        let mut b = BigInt::zero();

        let mut big_x = x.clone();
        let mut big_a = a.clone();
        let mut big_b = b.clone();

        loop {
            self.step(&mut x, &mut a, &mut b);
            self.step(&mut big_x, &mut big_a, &mut big_b);
            self.step(&mut big_x, &mut big_a, &mut big_b);
            if x == big_x {
                break;
            }
        }
        if b.modulus(&self.p) == big_b.modulus(&self.p) {
            return Err(SolverError::PollardConvergenceError);
        }
        let nom = BigInt::mod_sub(&a, &big_a, &self.big_p);
        let denom = BigInt::mod_sub(&big_b, &b, &self.big_p);
        let res = BigInt::modulus(
            &(BigInt::mod_inv(&denom, &self.big_p).unwrap() * &nom),
            &self.big_p,
        );
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rfc7919_groups::SupportedGroups, ElGamalKeyPair, ElGamalPP, ExponentElGamal};
    use curv::arithmetic::traits::Samplable;

    #[test]
    fn test_simple_pollard_wiki_example() {
        // from https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm_for_logarithms
        let simple_pollard = SimplePollard {
            p: &BigInt::from(1018),
            big_p: &BigInt::from(1019),
            alpha: &BigInt::from(2),
            beta: &BigInt::from(5),
        };
        let res = simple_pollard.run();
        assert!(res.is_ok());
        assert_eq!(res.clone().unwrap(), BigInt::from(10));
        assert_eq!(
            simple_pollard.beta,
            &BigInt::mod_pow(&simple_pollard.alpha, &res.unwrap(), &simple_pollard.big_p)
        );
    }

    #[test]
    fn test_convergence_error() {
        fn eval(x1: &BigInt, x2: &BigInt, p: &BigInt) -> Result<(), SolverError> {
            if x1.modulus(&p) == x2.modulus(&p) {
                return Err(SolverError::PollardConvergenceError);
            }
            Ok(())
        }
        let p = BigInt::from(5);
        let x11 = BigInt::from(6);
        let x21 = BigInt::from(21);
        let x22 = BigInt::from(22);

        let get_err = eval(&x11, &x21, &p);
        assert!(get_err.is_err());

        let get_err = eval(&x11, &x22, &p);
        assert!(get_err.is_ok());
    }

    #[test]
    #[ignore]
    fn test_exponent_elgamal_homomorphic_add_with_decryption() {
        let group_id = SupportedGroups::FFDHE2048;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message1 = BigInt::from(1_000);
        let random1 = BigInt::sample_below(&pp.q);
        let c1 =
            ExponentElGamal::encrypt_from_predefined_randomness(&message1, &keypair.pk, &random1)
                .unwrap();
        let message2 = BigInt::from(3);
        let random2 = BigInt::sample_below(&pp.q);
        let c2 =
            ExponentElGamal::encrypt_from_predefined_randomness(&message2, &keypair.pk, &random2)
                .unwrap();
        let c = ExponentElGamal::add(&c1, &c2).unwrap();

        // let m = ExponentElGamal::decrypt(&c, &keypair.sk).unwrap();
        // assert_eq!(BigInt::from(1_003), m);

        let big_p = c.pp.p.clone() + BigInt::one();
        let m = ExponentElGamal::decrypt_exp(&c, &keypair.sk).unwrap();

        let simple_pollard = SimplePollard::new(&c.pp.p, &big_p, &c.pp.g, &m);
        let res = simple_pollard.run();
        assert!(res.is_ok());
        let res = res.unwrap();
        assert_eq!(res, BigInt::from(1003));
        // return Err(ElGamalError::DecryptionError);
    }
}
