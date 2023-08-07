use secp256kfun::marker::{NonZero, Public, Secret, Zero};
use secp256kfun::{s, Scalar};
use std::collections::BTreeMap;

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

pub fn split_secret(
    secret: Scalar<Secret, NonZero>,
    num_shares: usize,
) -> Vec<Scalar<Secret, NonZero>> {
    assert!(num_shares >= 4);

    // We choose the byzantine fault tolerant threshold of 2f + 1
    let threshold = 2 * (num_shares / 3) + 1;

    // We encode the secret as the constant term of a otherwise
    // random polynomial of degree threshold - 1
    let mut coefficients = vec![secret.mark_zero()];
    let mut rng = rand::thread_rng();

    for _ in 1..threshold {
        coefficients.push(Scalar::random(&mut rng).mark_zero());
    }

    // Now we'll evaluate this polynomial at nonzero points to create the shares.
    (0..num_shares)
        .map(|i| {
            let scalar: Scalar<Secret, Zero> = Scalar::from((i + 1) as u32);
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

#[cfg(test)]
mod tests {
    use crate::shamir::{combine, evaluate_polynomial, split_secret};
    use secp256kfun::marker::{Public, Secret, Zero};
    use secp256kfun::Scalar;
    use std::collections::BTreeMap;

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
        let shares = split_secret(secret.clone(), 5);

        let threshold_of_shares: BTreeMap<u32, Scalar<Public, Zero>> = shares
            .iter()
            .enumerate()
            .take(4)
            .map(|(x, y)| ((x + 1) as u32, y.clone().public().mark_zero()))
            .collect();

        assert_eq!(secret, combine(&threshold_of_shares).non_zero().unwrap());
    }
}
