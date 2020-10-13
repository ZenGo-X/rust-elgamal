use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

#[allow(dead_code)]
mod elgamal_benches {
    use super::*;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::{ElGamal, ElGamalKeyPair, ElGamalPP,ElGamalCiphertext};


    struct EGPMulInput {
        ct: (ElGamalCiphertext, ElGamalCiphertext),
    }

    struct EGPowInput {
        ct: ElGamalCiphertext,
        constant: BigInt,
    }

    static RFC_GROUPS: [SupportedGroups; 5] = [
        SupportedGroups::FFDHE2048,
        SupportedGroups::FFDHE3072,
        SupportedGroups::FFDHE4096,
        SupportedGroups::FFDHE6144,
        SupportedGroups::FFDHE8192,
    ];
    static BIT_PARAMS: [usize; 2] = [1024, 2048];
    static MSG_TUPLES: [(u32,u32); 6] = [(9,3), (90,30), (900,300), (9000, 3000), (90000, 30000), (900000, 300000)];


    fn keypair_from_rfc7919(group_id: SupportedGroups) -> ElGamalKeyPair {
        let p_point = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&p_point);
        keypair
    }

    fn elgamal_mul(cipher_tuple: &EGPMulInput) {
        ElGamal::mul(&cipher_tuple.ct.0, &cipher_tuple.ct.1);
    }

    fn elgamal_pow(data: &EGPowInput) {
        ElGamal::pow(&data.ct, &data.constant);
    }

    fn elgamal_multiply(group_id: SupportedGroups, msg_params: &(u32,u32)) {
        // let pp = ElGamalPP::generate(bit_size);
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message1 = BigInt::from(msg_params.0);
        let c1 = ElGamal::encrypt(&message1, &keypair.pk).unwrap();
        let message2 = BigInt::from(msg_params.1);
        let c2 = ElGamal::encrypt(&message2, &keypair.pk).unwrap();
        let c = ElGamal::mul(&c1, &c2).unwrap();
        let _message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
    }

    fn elgamal_power(group_id: SupportedGroups, msg_params: &(u32,u32)) {
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(msg_params.0);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let constant = BigInt::from(msg_params.1);
        let c_tag = ElGamal::pow(&c, &constant);
        let _message_tag = ElGamal::decrypt(&c_tag, &keypair.sk).unwrap();
    }

    fn elgamal_encrypt_decrypt_rfc7919(group_id: SupportedGroups) {
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(13);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let _message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
    }

    fn keypairs_from_rfc7919(c: &mut Criterion) {
        let mut group = c.benchmark_group("keypairs_from_rfc7919");

        for group_id in RFC_GROUPS.iter() {
            for msg in MSG_TUPLES.iter() {
                let bench_id = format!(" rfc_id: {}, msg: {:?}", group_id, msg);
                group.bench_with_input(
                    BenchmarkId::from_parameter(bench_id),
                    group_id,
                    |b, group_id| {
                        b.iter(|| keypair_from_rfc7919(*group_id));
                    },
                );
            }
        }
        group.finish();
    }

    fn multiply(c: &mut Criterion) {
        let mut group = c.benchmark_group("multiply");
        for group_id in RFC_GROUPS.iter()  {
            for msg in MSG_TUPLES.iter() { 
                let bench_id = format!("group_id: {}, msg: {:?}", group_id, msg);
                group.bench_with_input(
                    BenchmarkId::from_parameter(bench_id),
                    group_id,
                    |b, group_id| {
                        b.iter(|| elgamal_multiply(*group_id, &msg));
                    },
                );
            }
        }
        group.finish();
    }

    fn power(c: &mut Criterion) {
        let mut group = c.benchmark_group("power");
        for group_id in RFC_GROUPS.iter() {
            for msg in MSG_TUPLES.iter() {
                let bench_id = format!("group_id: {}, msg: {:?}", group_id, msg);
                group.bench_with_input(
                    BenchmarkId::from_parameter(bench_id),
                    group_id,
                    |b, group_id| {
                        b.iter(|| elgamal_power(*group_id, &msg));
                    },
                );
            }
        }
        group.finish();
    }

    fn eg_pow(c: &mut Criterion) {
        let mut group = c.benchmark_group("elgamal_pow");
        // static BIT_SIZES: [usize; 2] = [1024, 2048];

        let mut pow_data:Vec<(EGPowInput, SupportedGroups, (u32,u32))> = Vec::new();

        for group_id in RFC_GROUPS.iter() {    
            let pp = ElGamalPP::generate_from_rfc7919(*group_id);
            for msg in MSG_TUPLES.iter() {
                let ct = ElGamalCiphertext {c1: BigInt::from(msg.0), c2: BigInt::from(msg.1), pp: pp.clone()};
                let constant = BigInt::from(msg.0);
                pow_data.push((EGPowInput {ct, constant}, *group_id, *msg));
            }
        }


        for data in pow_data.iter() {
            let bench_id = format!("group_id: {}, msg: {:?}", data.1, data.2);
            group.bench_with_input(
                BenchmarkId::from_parameter(bench_id),
                data,
                |b, data| {
                    b.iter(|| elgamal_pow(&data.0));
                },
            );
        }
        group.finish();
    }

    fn eg_mul(c: &mut Criterion) {
        let mut group = c.benchmark_group("elgamal_mul");
        // static BIT_SIZES: [usize; 2] = [1024, 2048];

        let mut cipher_texts: Vec<(EGPMulInput, SupportedGroups,  (u32, u32))> = Vec::new();
        
        for group_id in RFC_GROUPS.iter() {    
            let pp = ElGamalPP::generate_from_rfc7919(*group_id);
            for msg in MSG_TUPLES.iter() {
                let c1 = ElGamalCiphertext {c1: BigInt::from(msg.0), c2: BigInt::from(msg.1), pp: pp.clone()};
                let c2 = ElGamalCiphertext {c1: BigInt::from(msg.1), c2: BigInt::from(msg.0), pp: pp.clone()};
                cipher_texts.push((EGPMulInput {ct: (c1, c2)}, *group_id, *msg));
            }
        }
        
        for cipher_tuple in cipher_texts.iter() {  
            let bench_id= format!("group_id: {}, msg: {:?}", cipher_tuple.1, cipher_tuple.2);
                group.bench_with_input( 
                    BenchmarkId::from_parameter(bench_id),
                    // BenchmarkId::new("cipher_texts", cipher_tuple)
                    &cipher_tuple,
                    |b, &cipher_tuple| {
                        b.iter(|| elgamal_mul(&cipher_tuple.0));
                    },
                );
            }
        group.finish();

    }

    criterion_group! {
        name = benches;
        // config = Criterion::default();
        config = Criterion::default().significance_level(0.1).sample_size(40);
        targets =
            keypairs_from_rfc7919,
            eg_mul,
            eg_pow,
            multiply,
            power,
    }
}

criterion_main!(elgamal_benches::benches);
