use curv::arithmetic::traits::{ConvertFrom, Modulo};
use curv::BigInt;

// see https://en.wikipedia.org/wiki/Pollard%27s_rho_algorithm_for_logarithms#:~:text=Pollard's%20rho%20algorithm%20for%20logarithms%20is%20an%20algorithm%20introduced%20by,solve%20the%20integer%20factorization%20problem.&text=of%20the%20equation-,.,using%20the%20Extended%20Euclidean%20algorithm

const POLLARD_PARTITION_N: u32 = 3;
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
        match ConvertFrom::_from(&x.modulus(&BigInt::from(POLLARD_PARTITION_N))) {
            0 => {
                *x = BigInt::mod_mul(x, x, self.big_p);
                *a = BigInt::mod_mul(a, &BigInt::from(2), self.p);
                *b = BigInt::mod_mul(b, &BigInt::from(2), self.p);
            }
            1 => {
                *x = BigInt::mod_mul(x, self.alpha, self.big_p);
                *a = BigInt::mod_add(a, &BigInt::one(), self.big_p);
            }
            _ => {
                *x = BigInt::mod_mul(x, self.beta, self.big_p);
                *b = BigInt::mod_add(b, &BigInt::one(), self.p);
            }
        };
    }

    pub fn run(&self) -> BigInt {
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
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pollard() {
        let simple_pollard = SimplePollard {
            p: &BigInt::from(1018),
            big_p: &BigInt::from(1019),
            alpha: &BigInt::from(2),
            beta: &BigInt::from(5),
        };
        let res = simple_pollard.run();
        assert_eq!(res, BigInt::from(1010));
    }
}
