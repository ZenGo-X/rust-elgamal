use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

#[allow(dead_code)]
mod elgamal_benches {
    use super::*;
    use curv::BigInt;
    use elgamal::rfc7919_groups::SupportedGroups;
    use elgamal::{ElGamal, ElGamalKeyPair, ElGamalPP};

    static RFC_GROUPS: [SupportedGroups; 5] = [
        SupportedGroups::FFDHE2048,
        SupportedGroups::FFDHE3072,
        SupportedGroups::FFDHE4096,
        SupportedGroups::FFDHE6144,
        SupportedGroups::FFDHE8192,
    ];
    static BIT_PARAMS: [usize; 2] = [1024, 2048];
    static MSG_PARAMS: [u32; 2] = [9, 3];

    fn keypair_from_rfc7919(group_id: SupportedGroups) -> ElGamalKeyPair {
        let p_point = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&p_point);
        keypair
    }

    fn keypair_from_bits(bit_size: usize) -> ElGamalKeyPair {
        let p_point = ElGamalPP::generate(bit_size);
        let keypair = ElGamalKeyPair::generate(&p_point);
        keypair
    }

    fn elgamal_multiply(bit_size: usize, msg_params: &[u32; 2]) {
        let pp = ElGamalPP::generate(bit_size);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message1 = BigInt::from(msg_params[0]);
        let c1 = ElGamal::encrypt(&message1, &keypair.pk).unwrap();
        let message2 = BigInt::from(msg_params[1]);
        let c2 = ElGamal::encrypt(&message2, &keypair.pk).unwrap();
        let c = ElGamal::mul(&c1, &c2).unwrap();
        let _message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
    }

    fn elgamal_power(group_id: SupportedGroups, msg_params: &[u32; 2]) {
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(msg_params[0]);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let constant = BigInt::from(msg_params[1]);
        let c_tag = ElGamal::pow(&c, &constant);
        let _message_tag = ElGamal::decrypt(&c_tag, &keypair.sk).unwrap();
    }

    // #[inline]
    fn elgamal_encrypt_decrypt_rfc7919(group_id: SupportedGroups) {
        let pp = ElGamalPP::generate_from_rfc7919(group_id);
        let keypair = ElGamalKeyPair::generate(&pp);
        let message = BigInt::from(13);
        let c = ElGamal::encrypt(&message, &keypair.pk).unwrap();
        let _message_tag = ElGamal::decrypt(&c, &keypair.sk).unwrap();
    }

    fn keypairs_from_bits(c: &mut Criterion) {
        static BIT_SIZES: [usize; 2] = [1024, 2048];
        let mut group = c.benchmark_group("keypairs_from_bits");
        for bit_size in BIT_SIZES.iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(bit_size),
                bit_size,
                |b, &size| {
                    b.iter(|| keypair_from_bits(size));
                },
            );
        }
        group.finish();
    }

    fn keypairs_from_rfc7919(c: &mut Criterion) {
        let mut group = c.benchmark_group("keypairs_from_rfc7919");
        for group_id in RFC_GROUPS.iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(group_id),
                group_id,
                |b, group_id| {
                    b.iter(|| keypair_from_rfc7919(*group_id));
                },
            );
        }
        group.finish();
    }

    fn multiply(c: &mut Criterion) {
        let mut group = c.benchmark_group("multiply");
        for bit_size in BIT_PARAMS.iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(bit_size),
                bit_size,
                |b, bit_size| {
                    b.iter(|| elgamal_multiply(*bit_size, &MSG_PARAMS));
                },
            );
        }
        group.finish();
    }

    fn power(c: &mut Criterion) {
        let mut group = c.benchmark_group("power");
        for group_id in RFC_GROUPS.iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(group_id),
                group_id,
                |b, group_id| {
                    b.iter(|| elgamal_power(*group_id, &MSG_PARAMS));
                },
            );
        }
        group.finish();
    }

    fn encrypt_decrypt_rfc7919(c: &mut Criterion) {
        let mut group = c.benchmark_group("encrypt_decrypt_rfc7919");
        for group_id in RFC_GROUPS.iter() {
            group.bench_with_input(
                BenchmarkId::from_parameter(group_id),
                group_id,
                |b, group_id| {
                    b.iter(|| elgamal_encrypt_decrypt_rfc7919(*group_id));
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
            keypairs_from_bits,
            keypairs_from_rfc7919,
            encrypt_decrypt_rfc7919,
            multiply,
            power,
    }
}

criterion_main!(elgamal_benches::benches);
