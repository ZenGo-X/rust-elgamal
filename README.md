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

Although we currently are not aware of reference benchmarks.

## Contact

Feel free to [reach out](mailto:github@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x) for discussions on code and research.
