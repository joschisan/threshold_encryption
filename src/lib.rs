mod blinding;
mod dleq;
mod schnorr;
mod shamir;

use crate::blinding::blind_share;
use crate::shamir::split_secret;
use rand;
use secp256kfun::hash::HashAdd;
use secp256kfun::marker::{NonZero, Public};
use secp256kfun::{g, Point, Scalar, G};
use sha2::{Digest, Sha256};

fn secret_key() -> Scalar {
    Scalar::random(&mut rand::thread_rng())
}

fn public_key() -> Point {
    let sk = secret_key();

    g!(sk * G).normalize()
}
pub fn keypair() -> (Scalar, Point) {
    let sk = secret_key();
    let pk = g!(sk * G).normalize();

    (sk, pk)
}

struct PreimageDecryptionContract {
    hash: Sha256,
    amount: u64,
    blinded_shares: Vec<Scalar<Public, NonZero>>,
    ephemeral_pk: Point,
}

fn encrypt(
    preimage: &Scalar,
    amount: u64,
    ephemeral_sk: &Scalar,
    peers: &[Point],
) -> PreimageDecryptionContract {
    let hash = Sha256::default().add(preimage);

    let blinded_shares = split_secret(preimage.clone(), peers.len())
        .iter()
        .zip(peers)
        .map(|(share, peer_public_key)| blind_share(share, &ephemeral_sk, peer_public_key))
        .collect();

    let ephemeral_pk = g!(ephemeral_sk * G).normalize();

    PreimageDecryptionContract {
        hash,
        amount,
        blinded_shares,
        ephemeral_pk,
    }
}

fn contract_hash(contract: &PreimageDecryptionContract) -> Sha256 {
    contract
        .blinded_shares
        .iter()
        .fold(Sha256::default(), |acc, share| acc.add(share))
        .add(contract.hash.clone().finalize().as_slice())
        .add(&contract.amount.to_be_bytes())
        .add(contract.ephemeral_pk)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::blinding::unblind_share;
    use crate::dleq::prove;
    use crate::shamir::combine;
    use crate::{dleq, encrypt, keypair, secret_key};
    use secp256kfun::marker::{Public, Zero};
    use secp256kfun::{g, Point, Scalar};

    #[test]
    fn test_decryption() {
        let preimage = secret_key();
        let (ephemeral_sk, ephemeral_pk) = keypair();
        let (peer_sks, peer_pks): (Vec<Scalar>, Vec<Point>) = (0..5).map(|_| keypair()).unzip();

        let contract = encrypt(&preimage, 1000u64, &ephemeral_sk, &peer_pks);

        assert_eq!(contract.blinded_shares.len(), 5);

        let shared_secrets: Vec<Point> = peer_sks
            .iter()
            .map(|sk| g!(sk * ephemeral_pk).normalize())
            .collect();

        for ((sk, pk), shared_secret) in peer_sks.iter().zip(&peer_pks).zip(&shared_secrets) {
            let proof = prove(sk, pk, &ephemeral_pk, shared_secret);
            assert!(dleq::verify(&ephemeral_pk, pk, shared_secret, &proof));
        }

        let shares: Vec<Scalar<Public, Zero>> = contract
            .blinded_shares
            .iter()
            .zip(shared_secrets)
            .map(|(share, shared_secret)| unblind_share(&share.mark_zero(), &shared_secret))
            .collect();

        let threshold_of_shares: BTreeMap<u32, Scalar<Public, Zero>> = shares
            .iter()
            .enumerate()
            .take(4)
            .map(|(x, y)| ((x + 1) as u32, y.clone()))
            .collect();

        assert_eq!(preimage, combine(&threshold_of_shares).non_zero().unwrap());
    }
}
