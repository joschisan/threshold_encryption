use secp256kfun::hash::HashAdd;
use secp256kfun::marker::{NonZero, Public, Secret};
use secp256kfun::{g, s, Point, Scalar, G};
use sha2::Sha256;

pub fn sign(sk: &Scalar, message: Sha256) -> (Point, Scalar<Public, NonZero>) {
    let nonce = Scalar::<Secret, NonZero>::random(&mut rand::thread_rng());
    let r = g!(nonce * G).normalize();
    let e = Scalar::from_hash(message.add(r));
    let s = s!(nonce + e * sk)
        .public()
        .non_zero()
        .expect("The nonce is random");

    (r, s)
}

pub fn verify(pk: &Point, message: Sha256, (r, s): (Point, Scalar<Public, NonZero>)) -> bool {
    let e = Scalar::from_hash(message.add(r));

    g!(s * G) == g!(e * pk + r)
}

#[cfg(test)]
mod tests {
    use crate::keypair;
    use crate::schnorr::{sign, verify};
    use sha2::Sha256;

    #[test]
    fn test_sign_and_verify() {
        let (sk, pk) = keypair();
        let message = Sha256::default();
        let signature = sign(&sk, message.clone());

        assert!(verify(&pk, message, signature));
    }
}
