# rust-elgamal
Simple interface for ElGamal and Homomorphic-ElGamal cryptosystems. 

## Usage
```rust
        let group_id = SupportedGroups::FFDHE2048;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(13);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
        assert_eq!(message, message_tag);
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
