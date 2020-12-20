# rust-elgamal
Simple interface for ElGamal and Homomorphic-ElGamal cryptosystems. 

## Usage
````rust
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use elgamal::{
    rfc7919_groups::SupportedGroups, ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey,
    ElGamalPublicKey,ExponentElGamal,ElGamalCiphertext,
};

fn main() {

    // choose suitable field parameter, https://tools.ietf.org/html/rfc7919
    let group_id = SupportedGroups::FFDHE2048;

    let alice_pp = ElGamalPP::generate_from_rfc7919(group_id);

    // create a public, secret keypair
    let alice_key_pair = ElGamalKeyPair::generate(&alice_pp);


    // basic en/decryption roundtrip
    let message = BigInt::from(13);
    let cipher = ElGamal::encrypt(&message, &alice_key_pair.pk).unwrap();
    let message_tag = ElGamal::decrypt(&cipher, &alice_key_pair.sk).unwrap();
    println!("basic encryption: message: {}, decrypted: {}", message, message_tag);


    // homomorphic multiplication
    let factor_1 = BigInt::from(13);
    let factor_2 = BigInt::from(9);

    let cipher = ElGamal::encrypt(&factor_1, &alice_key_pair.pk).unwrap();
    let constant_cipher = ElGamal::encrypt(&factor_2, &alice_key_pair.pk).unwrap();

    // homomorphic multiplication in cipher space
    let product_cipher = ElGamal::mul(&cipher, &constant_cipher).unwrap();

    // decrypt homomorphic product
    let product_tag = ElGamal::decrypt(&product_cipher, &alice_key_pair.sk).unwrap();
    println!(" factor1: {} * factor 2: {} = {}; decrypted homomorphic product: {}", factor_1, factor_2, &factor_1 * &factor_2, product_tag);


    // homomorphic (pow) addition
    // note to self: we now have (g^r, g^m * h^r) instead of (g^r, m * h^r)
    // data set:
    let data = vec![BigInt::from(1),BigInt::from(10), BigInt::from(100)];
    let randomness = vec![BigInt::sample_below(&alice_pp.q), BigInt::sample_below(&alice_pp.q), BigInt::sample_below(&alice_pp.q)];

    // encrypt each data point 
    let mut ciphers: Vec<ElGamalCiphertext> = Vec::new();
    for (idx, number) in data.iter().enumerate() {
        let c = ExponentElGamal::encrypt_from_predefined_randomness(&number, &alice_key_pair.pk, &randomness[idx]).unwrap();
        ciphers.push(c);
    }

    // finally, we add the data
    let n = ciphers.len();
    let mut addition_cipher: ElGamalCiphertext = ExponentElGamal::add(&ciphers[0], &ciphers[1]).unwrap();
    for idx in 2..n {
        addition_cipher = ExponentElGamal::add(&ciphers[idx], &addition_cipher).unwrap();
    }

    // and now we decrypt and due to the exponentiation we end up with g^m
    let c_tag =  ExponentElGamal::decrypt_exp(&addition_cipher, &alice_key_pair.sk).unwrap();

    // and we're super inefficiently brute-forcing g^i mod p to validate the raw sum
    for i in 0..1_000_000 {
        let res = BigInt::mod_pow(&alice_key_pair.pk.pp.g, &BigInt::from(i), &alice_key_pair.pk.pp.p);
        if res.eq(&c_tag) {
            println!("result: {}", i);
            break;
        }
    }

}

```
## Tests  

Several tests are included:  

```rust
cargo test --lib
```  

Please note that the test for `generate_safe` is not part of the default test run due to the potentially long runtime. To run the expensive tests:  

```rust
cargo test --lib  -- --ignored
```  

## Benches  

Benchmarks are also included:

```rust
cargo bench
```  

The benchmarks are created by[criterion.rs](https://github.com/bheisler/criterion.rs) and the default reports include pretty cool plots, which are best with `gnuplot` installed, e.g., `brew install gnuplot`.  The benchmark reports can found in `../target/criterion/report` and `open index.html` should do.

To run the benches without plots, or with any of the other [criterion.rs options](https://bheisler.github.io/criterion.rs/book/user_guide/command_line_options.html), use  

```bash
cargo bench --bench elgamal_benches -- --noplot
```  

See `benches/examples` for a full results set.  


## Contact

Feel free to [reach out](mailto:github@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x) for discussions on code and research.
