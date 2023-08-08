# Threshold Encryption of LN Payment Preimage

This document drafts a alternative mechanism to the threshold encryption currently used. We achieve the following design goals:
* only use secp256k1, no pairing crypto 
* no offer mechanism needed to bind hash and amount to encrypted preimage, user can give decryption contract to the gateway
* on broadcast space consumption is asymtotically linear in the number of guardians

With this scheme we need a static secp256k1 key pair for every guardian, which have to be setup in the config generation. 
    
## Decryption Contract User Protocol

* use shamir secret sharing to split secret primage interpreted as a secp256k1 scalar
* create ephemeral keypair for this decryption contract
* compute a shared secret with every guardian from the ephemeral private key and the guardians static public keys with a Elliptic Curve Diffie Hellman key exchange
* blind a shamir secret share with the hash of the corresponding guardians shared secret
* finally sign the message of the hash, amount and blinded shamir secret shares
* send the decryption contract consisting of the ephemeral public key and the signed message to the gateway

Now the gateway founds a transaction with the decryption contract as output.

## Decryption Contract Guardian Protocol
* verify signature for the ephemeral public key
* compute shared secret with the user from static private key and ephemeral public key
* compute discrete log equality proof to to proof that the shared secret is correct
* send decryption share consisting of shared secret and proof to the broadcast
* wait for a threshold of decryption shares with valid proofs
* unblind the corresponding threshold of shares with the hashes of the shared secrets
* compute the secret preimage, refund to gateway if any unblinded shares is not a valid secp256k1 scalar
* compute hash, refund if it does not match the contracts hash

### Security Argument for User

The only way to obtain the shared secrets for a ephemeral keypair is to submit a valid decryption contract with this ephemeral keypair to the broadcast with the correct amount of funding. Since the user only signs valid decryption contracts and the guardians canot falsify the shares secrets the decryption is guaranteed to succeed, hence the funding will be accesible with the ephemeral key pair. 

## Discrete Log Equality Proof

The proof allows a third party to verify the shared secret of a ECDH from the two public keys alone. It has been lifted from https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406. Assume that Alice and Bobe have the keypair (a,A) and (b,B) and have performed a ECDH with resulting shared secret point S. Now both parties can create a proof that S was the result of their ECDH. We consider Alice as an example

```
Alice:
 r = random nonce
 R1 = r*G
 R2 = r*B
 e = hash(R1,R2,A,S)
 s = r + e*a
 return e, s

Verifier:
 R1 = s*G - e*A 
 R2 = s*B - e*S
 e == hash(R1,R2,A,S)
```

## Space Optimization

The broadcast space cost for the current design is

* 33 bytes for the ephemeral public key
* 65 bytes for the ephemeral signature
* n * 32 bytes for the blinded shamir secret shares
* (2f+1) * 33 for reveiling the shared secret points 
* (2f+1) * 64 for the discrete log equality proofs

We can optimize this by using the feldman scheme for validated shamir secret sharing. The scheme creates a polynomial commitment which the user would sign as part of the decryption contract. This enables a guardian to verify a correct secret share, hence the the guardian would only send the shared secret point and DLEQ to proof that the shamir secret share that it obtained by unblinding was invalid, even though it unblinded it correctly. Therefore, If the user is correct, guardians only have to send the 32 bytes shamir secret share. The polynomial commitment is of size (2f + 1) * 33. This optimization therefore saves us (2f+1) * 64 bytes which asymptotically approaches about 40% for increasing f.

However. this introduces a second codepath only triggered when the user misbehaves by sending invalid shamir secret shares. I would therefore stick to the current design, at least for the initial implementation.
