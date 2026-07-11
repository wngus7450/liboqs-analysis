# HAETAE integration

This directory integrates the HAETAE reference implementation from the NIST
Round 1 Additional Signatures submission package.

- Source package: `HAETAE-submission.zip`
- Download URL: `https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/submission-pkg/HAETAE-submission.zip`
- SHA-256 observed during integration:
  `6ad5bc32b8bed7ba9c6405cf6f40c090a10d603baed9ec77c20a8b644f909d55`
- Integrated implementation: `Reference_Implementation`
- Exposed liboqs algorithm name: `HAETAE`
- HAETAE parameter mode: `HAETAE_MODE=2`
- OQS public key length: `992`
- OQS secret key length: `1408`
- OQS signature length: `1463`

The bundled `randombytes.c` is not compiled. The copied `randombytes.h` maps
HAETAE's local `randombytes` call to liboqs `OQS_randombytes` so that key
generation follows the same randomness path as the rest of this reduced liboqs
build.

HAETAE is exposed through the normal `OQS_SIG` interface:

```c
OQS_SIG *sig = OQS_SIG_new("HAETAE");
OQS_SIG_keypair(sig, public_key, secret_key);
OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
```

The local KAT tool can be rebuilt and run with:

```sh
make kat_sig
./build/tests/kat_sig HAETAE
```
