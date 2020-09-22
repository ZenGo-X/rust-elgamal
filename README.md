# rust-elgamal
Simple interface for ElGamal and Homomorphic-ElGamal cryptosystems. 

## Usage
```rust

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
```

## Contact

Feel free to [reach out](mailto:github@kzencorp.com) or join ZenGo X [Telegram](https://t.me/zengo_x) for discussions on code and research.
