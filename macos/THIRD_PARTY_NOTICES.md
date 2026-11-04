# Third-party cryptography

bwssh is licensed under Apache 2.0 (see the repository LICENSE).

Argon2 is vendored from the upstream reference implementation, tag `20190702`:
https://github.com/P-H-C/phc-winner-argon2/tree/20190702

The Argon2 sources retain their original headers and are used under Apache 2.0.
Its BLAKE2 code is copyright Samuel Neves and available under CC0 or Apache 2.0.
The upstream license is included at `Sources/CBwCrypto/argon2/LICENSE`.

OpenSSH's `bcrypt_pbkdf.c`, `blowfish.c`, and `blf.h` are vendored without changes
from tag `V_9_9_P2`:
https://github.com/openssh/openssh-portable/tree/V_9_9_P2/openbsd-compat

They retain the ISC / BSD license notices of Ted Unangst and Niels Provos.
The packaged app includes copies of these source files and their full notices.
The local `includes.h` and `crypto_api.h` adapters use Apple's CommonCrypto SHA-512
and a volatile zeroing function. No external crypto process or dynamic library is required.
