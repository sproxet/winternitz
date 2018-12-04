# winternitz

winternitz is a small crate implementing a quantum-resistant one-time signature
scheme, the `LDWM_SHA256_M20_W8` variant of LDWM (but not MTS) as described in
https://tools.ietf.org/html/draft-mcgrew-hash-sigs-02.

## Usage

***Each private key may only be used to sign ONE message. Signing multiple
messages with a single key could reveal your private key data.***

```rust
extern crate rand;
extern crate winternitz;

use rand::{thread_rng, RngCore};

fn main() {
	// Fill up the space of a new private key with entropy.
	let mut privkey = [0; winternitz::PRIVKEY_SIZE];
	thread_rng().fill_bytes(&mut privkey);

	// Generate your public key from your private key.
	let mut pubkey = [0; winternitz::PUBKEY_SIZE];
	winternitz::derive_pubkey(&privkey, &mut pubkey).unwrap();

	// Sign a message.
	let msg = b"squeamish ossifrage";
	let mut sig = [0; winternitz::SIG_SIZE];
	winternitz::sign(&privkey, msg, &mut sig).unwrap();

	// Verify a signature.
	assert!(winternitz::verify(&pubkey, msg, &sig).unwrap());

	Ok(())
}
```
