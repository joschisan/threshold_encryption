use secp256kfun::hash::HashAdd;
use secp256kfun::marker::{NonZero, Secret};
use secp256kfun::{g, s, Point, Scalar, G};
use sha2::Sha256;

pub struct Proof(pub(crate) Point, Scalar, Scalar);

pub fn prove(ephemeral_pk: &Point, sk: &Scalar) -> Proof {
    let pk = g!(sk * G).normalize();
    let shared_point = g!(sk * ephemeral_pk).normalize();
    let nonce = Scalar::<Secret, NonZero>::random(&mut rand::thread_rng());

    let r1 = g!(nonce * G).normalize();
    let r2 = g!(nonce * ephemeral_pk).normalize();

    let challenge = Sha256::default()
        .add(r1)
        .add(r2)
        .add(pk)
        .add(ephemeral_pk)
        .add(shared_point);

    let e = Scalar::<Secret, NonZero>::from_hash(challenge);
    let s = s!(nonce + e * sk).non_zero().expect("The nonce is random");

    Proof(shared_point, e, s)
}

pub(crate) fn verify(
    ephemeral_pk: &Point,
    peer_pk: &Point,
    Proof(shared_point, e, s): &Proof,
) -> bool {
    let r1 = g!(s * G - e * peer_pk).normalize();
    let r2 = g!(s * ephemeral_pk - e * shared_point).normalize();

    let challenge = Sha256::default()
        .add(r1)
        .add(r2)
        .add(peer_pk)
        .add(ephemeral_pk)
        .add(shared_point);

    e == &Scalar::<Secret, NonZero>::from_hash(challenge)
}

#[cfg(test)]
mod tests {
    use crate::dleq::{prove, verify};
    use crate::keypair;

    #[test]
    fn test_proof_symmetry() {
        let (sk_a, pk_a) = keypair();
        let (sk_b, pk_b) = keypair();

        let proof_a = prove(&pk_a, &sk_b);
        let proof_b = prove(&pk_b, &sk_a);

        assert_eq!(proof_a.0, proof_b.0);
        assert!(verify(&pk_a, &pk_b, &proof_a));
        assert!(verify(&pk_b, &pk_a, &proof_b));
    }
}
