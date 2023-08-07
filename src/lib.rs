use rand;
use secp256kfun::hash::HashAdd;
use secp256kfun::marker::{NonZero, Public, Secret, Zero};
use secp256kfun::{g, s, Point, Scalar, G};
use sha2::Sha256;
use std::collections::BTreeMap;

struct DLEQ(Point, Scalar, Scalar);

fn dleq(ephemeral_pk: &Point, sk: &Scalar) -> DLEQ {
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

    DLEQ(shared_point, e, s)
}

fn verify_dleq(ephemeral_pk: &Point, peer_pk: &Point, DLEQ(shared_point, e, s): &DLEQ) -> bool {
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

fn evaluate_polynomial(
    coefficients: &[Scalar<Secret, Zero>],
    x: Scalar<Secret, Zero>,
) -> Scalar<Secret, Zero> {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::<Secret, Zero>::zero(), |acc, coefficient| {
            s!(acc * x + coefficient)
        })
}

pub fn shamir_secret_sharing(
    secret: Scalar<Secret, NonZero>,
    num_shares: usize,
) -> Vec<Scalar<Secret, NonZero>> {
    assert!(num_shares >= 4);

    let threshold = 2 * (num_shares / 3) + 1;

    // We'll need to create a random polynomial of degree threshold - 1
    // where the constant term is the secret.
    let mut coefficients = vec![secret.mark_zero()];
    let mut rng = rand::thread_rng();

    for _ in 1..threshold {
        coefficients.push(Scalar::random(&mut rng).mark_zero());
    }

    // Now we'll evaluate this polynomial at nonzero points to create the shares.
    (1..=num_shares)
        .map(|i| {
            let scalar: Scalar<Secret, Zero> = Scalar::from(i as u32);
            evaluate_polynomial(&coefficients, scalar)
                .non_zero()
                .expect("The coefficients are random")
        })
        .collect()
}

pub fn lagrange_multiplier(shares: Vec<&u32>) -> Vec<Scalar<Secret, NonZero>> {
    shares
        .iter()
        .map(|i| {
            shares
                .iter()
                .filter(|j| *j != i)
                .map(|j| {
                    let i: Scalar = Scalar::from(**i).non_zero().expect("We start from 1");
                    let j: Scalar = Scalar::from(**j).non_zero().expect("We start from 1");

                    let denominator_inverse = s!(j - i)
                        .non_zero()
                        .expect("We filtered the case j == i")
                        .invert();

                    s!(j * denominator_inverse)
                })
                .reduce(|a, b| s!(a * b))
                .expect("We have at least one share")
        })
        .collect()
}

pub fn combine(shares: &BTreeMap<u32, Scalar<Public, Zero>>) -> Scalar<Public, Zero> {
    shares
        .values()
        .zip(lagrange_multiplier(shares.keys().collect()))
        .map(|(y, multiplier)| s!(y * multiplier))
        .reduce(|a, b| s!(a + b))
        .expect("We have at least one share")
        .public()
}

fn blind_share(
    share: &Scalar<Secret, NonZero>,
    ephemeral_sk: &Scalar<Secret, NonZero>,
    peer_public_key: &Point,
) -> Scalar<Public, Zero> {
    let shared_point = g!(ephemeral_sk * peer_public_key).normalize();
    let shared_secret = Sha256::default().add(shared_point);
    let blinding_factor = Scalar::<Secret, NonZero>::from_hash(shared_secret);

    s!(share + blinding_factor).public()
}

pub fn unblind_share(
    blinded_share: Scalar<Public, Zero>,
    shared_point: Point,
) -> Scalar<Public, Zero> {
    let shared_secret = Sha256::default().add(shared_point);
    let blinding_factor = Scalar::<Secret, NonZero>::from_hash(shared_secret);

    s!(blinded_share - blinding_factor).public()
}

fn threshold_encrypt(
    secret: &Scalar,
    peers: &[Point],
    ephemeral_sk: &Scalar,
) -> Vec<Scalar<Public, Zero>> {
    shamir_secret_sharing(secret.clone(), peers.len())
        .iter()
        .zip(peers)
        .map(|(share, peer_public_key)| blind_share(share, &ephemeral_sk, peer_public_key))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use secp256kfun::marker::{NonZero, Public, Secret, Zero};
    use secp256kfun::{g, Point, Scalar, G};

    use super::{
        blind_share, combine, dleq, evaluate_polynomial, shamir_secret_sharing, threshold_encrypt,
        unblind_share, verify_dleq, DLEQ,
    };

    fn keypair() -> (Scalar, Point) {
        let sk = Scalar::<Secret, NonZero>::random(&mut rand::thread_rng());
        let pk = g!(sk * G).normalize();

        (sk, pk)
    }

    #[test]
    fn test_dleq_proof_symmetry() {
        let (sk_a, pk_a) = keypair();
        let (sk_b, pk_b) = keypair();

        let proof_a = dleq(&pk_a, &sk_b);
        let proof_b = dleq(&pk_b, &sk_a);

        assert_eq!(proof_a.0, proof_b.0);
        assert!(verify_dleq(&pk_a, &pk_b, &proof_a));
        assert!(verify_dleq(&pk_b, &pk_a, &proof_b));
    }

    #[test]
    fn test_evaluate_polynomial() {
        // Define coefficients for the polynomial: 4x^3 + 3x^2 + 2x + 1
        let coefficients: Vec<Scalar<Secret, Zero>> = vec![
            Scalar::from(1),
            Scalar::from(2),
            Scalar::from(3),
            Scalar::from(4),
        ];

        let expected: Scalar<Secret, Zero> = Scalar::from(49);

        assert_eq!(
            expected,
            evaluate_polynomial(&coefficients, Scalar::from(2))
        );
    }

    #[test]
    fn test_splitting_and_combining_secret() {
        // We split the secret between five peers such that four peers can reconstruct it
        let secret = Scalar::from(42u32).non_zero().unwrap();
        let shares = shamir_secret_sharing(secret.clone(), 5);

        let threshold_of_shares: BTreeMap<u32, Scalar<Public, Zero>> = shares
            .iter()
            .enumerate()
            .take(4)
            .map(|(x, y)| ((x + 1) as u32, y.clone().public().mark_zero()))
            .collect();

        assert_eq!(secret, combine(&threshold_of_shares).non_zero().unwrap());
    }

    #[test]
    fn test_blinding_and_unblinding_shares() {
        let (ephemeral_sk, ..) = keypair();
        let (.., peer_pk) = keypair();

        let share = Scalar::from(42u32).non_zero().unwrap();
        let blinded_share = blind_share(&share, &ephemeral_sk, &peer_pk);

        let shared_point = g!(ephemeral_sk * peer_pk).normalize();

        assert_eq!(
            share,
            unblind_share(blinded_share, shared_point)
                .non_zero()
                .unwrap()
        );
    }

    #[test]
    fn test_integration() {
        let secret = Scalar::random(&mut rand::thread_rng());

        let (ephemeral_sk, ephemeral_pk) = keypair();

        let (peer_sks, peer_pks): (Vec<Scalar>, Vec<Point>) = (0..5).map(|_| keypair()).unzip();

        let blinded_shares = threshold_encrypt(&secret, &peer_pks, &ephemeral_sk);

        let dleqs: Vec<DLEQ> = peer_sks.iter().map(|sk| dleq(&ephemeral_pk, &sk)).collect();

        for (pk, dleq_proof) in peer_pks.iter().zip(&dleqs) {
            assert!(verify_dleq(&ephemeral_pk, &pk, &dleq_proof));
        }

        let shares: Vec<Scalar<Public, Zero>> = dleqs
            .iter()
            .zip(blinded_shares.iter())
            .map(|(dleq_proof, blinded_share)| unblind_share(*blinded_share, dleq_proof.0))
            .collect();

        let threshold_of_shares: BTreeMap<u32, Scalar<Public, Zero>> = shares
            .iter()
            .enumerate()
            .take(4)
            .map(|(x, y)| ((x + 1) as u32, y.clone()))
            .collect();

        assert_eq!(secret, combine(&threshold_of_shares).non_zero().unwrap());
    }
}
