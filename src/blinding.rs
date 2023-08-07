use secp256kfun::hash::HashAdd;
use secp256kfun::marker::{NonZero, Public, Secret, Zero};
use secp256kfun::{g, s, Point, Scalar};
use sha2::Sha256;

pub(crate) fn blind_share(
    share: &Scalar<Secret, NonZero>,
    ephemeral_sk: &Scalar<Secret, NonZero>,
    peer_public_key: &Point,
) -> Scalar<Public, NonZero> {
    let shared_point = g!(ephemeral_sk * peer_public_key).normalize();
    let shared_secret = Sha256::default().add(shared_point);
    let blinding_factor = Scalar::<Secret, NonZero>::from_hash(shared_secret);

    s!(share + blinding_factor)
        .public()
        .non_zero()
        .expect("The blind factor is random")
}

pub fn unblind_share(
    blinded_share: Scalar<Public, Zero>,
    shared_point: Point,
) -> Scalar<Public, Zero> {
    let shared_secret = Sha256::default().add(shared_point);
    let blinding_factor = Scalar::<Secret, NonZero>::from_hash(shared_secret);

    s!(blinded_share - blinding_factor).public()
}

#[cfg(test)]
mod tests {
    use crate::blinding::{blind_share, unblind_share};
    use crate::keypair;
    use secp256kfun::{g, Scalar};

    #[test]
    fn test_blinding_and_unblinding_shares() {
        let (ephemeral_sk, ..) = keypair();
        let (.., peer_pk) = keypair();

        let share = Scalar::from(42u32).non_zero().unwrap();
        let blinded_share = blind_share(&share, &ephemeral_sk, &peer_pk).mark_zero();

        let shared_point = g!(ephemeral_sk * peer_pk).normalize();

        assert_eq!(
            share,
            unblind_share(blinded_share, shared_point)
                .non_zero()
                .unwrap()
        );
    }
}
