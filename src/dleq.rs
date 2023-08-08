use secp256kfun::hash::HashAdd;
use secp256kfun::marker::{NonZero, Secret};
use secp256kfun::{g, s, Point, Scalar, G};
use sha2::Sha256;

pub fn prove(
    sk: &Scalar,
    pk: &Point,
    ephemeral_pk: &Point,
    shared_point: &Point,
) -> (Scalar, Scalar) {
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

    (e, s)
}

pub(crate) fn verify(
    ephemeral_pk: &Point,
    peer_pk: &Point,
    shared_point: &Point,
    (e, s): &(Scalar, Scalar),
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
    use secp256kfun::g;

    #[test]
    fn test_proof_symmetry() {
        let (sk_a, pk_a) = keypair();
        let (sk_b, pk_b) = keypair();

        let shared_point = g!(sk_a * pk_b).normalize();

        let proof_a = prove(&sk_a, &pk_a, &pk_b, &shared_point);
        let proof_b = prove(&sk_b, &pk_b, &pk_a, &shared_point);

        assert!(verify(&pk_a, &pk_b, &shared_point, &proof_b));
        assert!(verify(&pk_b, &pk_a, &shared_point, &proof_a));
    }
}
