use curv::arithmetic::traits::Modulo;
use curv::BigInt;
use std::collections::HashMap;
use uuid::Uuid;

use crate::rfc7919_groups::{SupportedGroups, SRG};
use crate::{
    ElGamal, ElGamalKeyPair, ElGamalPP, ElGamalPrivateKey, ElGamalPublicKey, ExponentElGamal,
};

#[derive(Debug, PartialEq, Clone)]
pub struct Party {
    id: u32,
    group_id: SupportedGroups,
    keypair: ElGamalKeyPair,
    shared_keypairs: HashMap<String, ElGamalKeyPair>,
}

impl Party {
    pub fn new(id: u32, group_id: SupportedGroups) -> Self {
        let pp = ElGamalPP::generate_from_rfc7919(group_id.clone());
        let keypair = ElGamalKeyPair::generate(&pp);
        let shared_keypairs: HashMap<String, ElGamalKeyPair> = HashMap::new();

        Party {
            id,
            group_id,
            keypair,
            shared_keypairs,
        }
    }

    pub fn create_shared_secret(
        &mut self,
        session_id: String,
        pk: BigInt,
    ) -> Result<(), &'static str> {
        if !self.shared_keypairs.get(&session_id).is_none() {
            return Err("Shared keypair already exists.");
        }

        let shared_secret = BigInt::mod_pow(&pk, &self.keypair.sk.x, &self.keypair.pk.pp.p);

        let shared_pk =
            BigInt::mod_pow(&self.keypair.pk.pp.g, &shared_secret, &self.keypair.pk.pp.p);

        let shared_keypair = ElGamalKeyPair {
            pk: ElGamalPublicKey {
                pp: self.keypair.pk.pp.clone(),
                h: shared_pk,
            },
            sk: ElGamalPrivateKey {
                pp: self.keypair.pk.pp.clone(),
                x: shared_secret,
            },
        };

        self.shared_keypairs.insert(session_id, shared_keypair);

        Ok(())
    }

    pub fn get_keypair(&self) -> ElGamalKeyPair {
        self.keypair.clone()
    }

    pub fn get_shared_keypair(&self, session_id: String) -> Result<ElGamalKeyPair, &'static str> {
        match self.shared_keypairs.get(&session_id) {
            Some(kp) => Ok(kp.clone()),
            None => Err("Referenced KeyPair does not exist."),
        }
    }
}

// #[derive(Debug, PartialEq, Clone)]
pub struct KeyExchange {
    session_id: String,
    group_id: SupportedGroups,
    party_one_pk: Option<BigInt>,
    party_two_pk: Option<BigInt>,
}

impl KeyExchange {
    pub fn new(group_id: SupportedGroups) -> Self {
        KeyExchange {
            session_id: Uuid::new_v4().to_string(),
            group_id,
            party_one_pk: None,
            party_two_pk: None,
        }
    }

    pub fn update_pk(
        &mut self,
        party_one_pk: Option<BigInt>,
        party_two_pk: Option<BigInt>,
    ) -> Result<(), &'static str> {
        if party_one_pk.is_none() && party_two_pk.is_none() {
            return Err("Invalid party values. At least one party key != None.");
        }
        if self.party_one_pk.is_some() && party_one_pk.is_none() {
            return Err("PK reset to None is not a valid option");
        } else {
            self.party_one_pk = party_one_pk;
        }

        if self.party_two_pk.is_some() && party_two_pk.is_none() {
            return Err("PK reset to None is not a valid option");
        } else {
            self.party_two_pk = party_two_pk;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::arithmetic::traits::Samplable;

    fn test_new_key_exchange() {}

    fn test_update_key_exchange_good() {}

    fn test_update_key_exchange_bad() {}
    #[test]
    fn test_party_new() {
        let group_id = SupportedGroups::FFDHE2048;

        let alice: Party = Party::new(1, group_id.clone());
        let bob: Party = Party::new(2, group_id.clone());

        assert_eq!(bob.group_id, alice.group_id);
        assert_eq!(alice.keypair.pk.pp, alice.keypair.sk.pp);
        assert_eq!(bob.keypair.pk.pp, bob.keypair.sk.pp);
    }

    #[test]
    fn test_shared_secret() {
        let group_id = SupportedGroups::FFDHE2048;
        let session_id = Uuid::new_v4().to_string();

        let mut alice: Party = Party::new(1, group_id.clone());
        let mut bob: Party = Party::new(2, group_id.clone());

        let res_1 = alice.create_shared_secret(session_id.clone(), bob.keypair.pk.h.clone());
        let res_2 = bob.create_shared_secret(session_id.clone(), alice.keypair.pk.h.clone());
        assert!(res_1.is_ok());
        assert!(res_2.is_ok());

        let bob_shared_kp = bob.get_shared_keypair(session_id.clone()).unwrap();
        let alice_shared_kp = alice.get_shared_keypair(session_id.clone()).unwrap();
        assert_eq!(bob_shared_kp.sk.x, alice_shared_kp.sk.x);

        assert_ne!(alice.get_keypair().pk.h, alice_shared_kp.pk.h);
        assert_ne!(bob.get_keypair().pk.h, bob_shared_kp.pk.h);
    }

    #[test]
    fn test_encryption() {
        let group_id = SupportedGroups::FFDHE2048;
        let session_id = Uuid::new_v4().to_string();

        let mut alice: Party = Party::new(1, group_id.clone());
        let mut bob: Party = Party::new(2, group_id.clone());

        let res_1 = alice.create_shared_secret(session_id.clone(), bob.keypair.pk.h.clone());
        let res_2 = bob.create_shared_secret(session_id.clone(), alice.keypair.pk.h.clone());

        let bob_shared_kp = bob.get_shared_keypair(session_id.clone()).unwrap();
        let alice_shared_kp = alice.get_shared_keypair(session_id.clone()).unwrap();

        let message = BigInt::from(13);
        let c_alice = ElGamal::encrypt(&message, &alice_shared_kp.pk).unwrap();
        let c_bob = ElGamal::encrypt(&message, &bob_shared_kp.pk).unwrap();
        assert_ne!(c_alice, c_bob);

        let message_tag_alice = ElGamal::decrypt(&c_bob, &alice_shared_kp.sk).unwrap();
        let message_tag_bob = ElGamal::decrypt(&c_alice, &bob_shared_kp.sk).unwrap();
        assert_eq!(message_tag_bob, message_tag_alice);
        assert_eq!(message, message_tag_alice);
        assert_eq!(message_tag_bob, message);
    }
    #[test]
    fn test_mul_encryption() {
        let group_id = SupportedGroups::FFDHE2048;
        let session_id = Uuid::new_v4().to_string();

        let mut alice: Party = Party::new(1, group_id.clone());
        let mut bob: Party = Party::new(2, group_id.clone());

        alice.create_shared_secret(session_id.clone(), bob.keypair.pk.h.clone());
        bob.create_shared_secret(session_id.clone(), alice.keypair.pk.h.clone());

        let bob_shared_kp = bob.get_shared_keypair(session_id.clone()).unwrap();
        let alice_shared_kp = alice.get_shared_keypair(session_id.clone()).unwrap();

        let m1 = BigInt::from(13);
        let m2 = BigInt::from(9);

        let c1 = ElGamal::encrypt(&m1, &alice_shared_kp.pk).unwrap();
        let c2 = ElGamal::encrypt(&m2, &bob_shared_kp.pk).unwrap();
        let c = ElGamal::mul(&c1, &c2).unwrap();

        let message_tag_alice = ElGamal::decrypt(&c, &alice_shared_kp.sk).unwrap();
        let message_tag_bob = ElGamal::decrypt(&c, &bob_shared_kp.sk).unwrap();

        assert_eq!(message_tag_alice, message_tag_bob);
        assert_eq!(message_tag_alice, BigInt::from(117));

        let c1 = ElGamal::encrypt(&m1, &alice_shared_kp.pk).unwrap();
        let c2 = ElGamal::encrypt(&m2, &alice_shared_kp.pk).unwrap();
        let c = ElGamal::mul(&c1, &c2).unwrap();

        let message_tag_alice = ElGamal::decrypt(&c, &alice_shared_kp.sk).unwrap();
        let message_tag_bob = ElGamal::decrypt(&c, &bob_shared_kp.sk).unwrap();

        assert_eq!(message_tag_alice, message_tag_bob);
        assert_eq!(message_tag_alice, BigInt::from(117));
    }

    #[test]
    fn test_pow_encryption() {
        let group_id = SupportedGroups::FFDHE2048;
        let session_id = Uuid::new_v4().to_string();

        let mut alice: Party = Party::new(1, group_id.clone());
        let mut bob: Party = Party::new(2, group_id.clone());

        alice.create_shared_secret(session_id.clone(), bob.keypair.pk.h.clone());
        bob.create_shared_secret(session_id.clone(), alice.keypair.pk.h.clone());

        let bob_shared_kp = bob.get_shared_keypair(session_id.clone()).unwrap();
        let alice_shared_kp = alice.get_shared_keypair(session_id.clone()).unwrap();

        let msg = BigInt::from(13);
        let constant = BigInt::from(3);

        let c = ElGamal::encrypt(&msg, &alice_shared_kp.pk).unwrap();
        let c_tag = ElGamal::pow(&c, &constant);

        let message_tag_alice = ElGamal::decrypt(&c_tag, &alice_shared_kp.sk).unwrap();
        let message_tag_bob = ElGamal::decrypt(&c_tag, &bob_shared_kp.sk).unwrap();

        assert_eq!(message_tag_alice, message_tag_bob);
        assert_eq!(message_tag_alice, BigInt::from(2197));
    }

    #[test]
    fn test_exponent_add() {
        let group_id = SupportedGroups::FFDHE2048;
        let session_id = Uuid::new_v4().to_string();

        let mut alice: Party = Party::new(1, group_id.clone());
        let mut bob: Party = Party::new(2, group_id.clone());

        alice.create_shared_secret(session_id.clone(), bob.keypair.pk.h.clone());
        bob.create_shared_secret(session_id.clone(), alice.keypair.pk.h.clone());

        let bob_shared_kp = bob.get_shared_keypair(session_id.clone()).unwrap();
        let alice_shared_kp = alice.get_shared_keypair(session_id.clone()).unwrap();

        let message1 = BigInt::sample_below(&bob.keypair.pk.pp.q);
        let random1 = BigInt::sample_below(&bob.keypair.pk.pp.q);
        let c1 = ExponentElGamal::encrypt_from_predefined_randomness(
            &message1,
            &bob_shared_kp.pk,
            &random1,
        )
        .unwrap();

        let message2 = BigInt::sample_below(&alice.keypair.pk.pp.q);
        let random2 = BigInt::sample_below(&alice.keypair.pk.pp.q);
        let c2 = ExponentElGamal::encrypt_from_predefined_randomness(
            &message2,
            &alice_shared_kp.pk,
            &random2,
        )
        .unwrap();

        let c = ExponentElGamal::add(&c1, &c2).unwrap();
        let message_total = (&message1 + &message2).modulus(&alice.keypair.pk.pp.q);
        let random_total = (&random1 + &random2).modulus(&bob.keypair.pk.pp.q);
        let c_star = ExponentElGamal::encrypt_from_predefined_randomness(
            &message_total,
            &alice_shared_kp.pk,
            &random_total,
        )
        .unwrap();

        assert_eq!(c_star, c);

        let c_star = ExponentElGamal::encrypt_from_predefined_randomness(
            &message_total,
            &bob_shared_kp.pk,
            &random_total,
        )
        .unwrap();
        assert_eq!(c_star, c);
    }
}
