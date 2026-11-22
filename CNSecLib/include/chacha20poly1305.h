#ifndef KYBER_CHACHA20POLY1305_H
#define KYBER_CHACHA20POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include "kyber_export.h"

#define CHACHA20_KEYBYTES   32
#define CHACHA20_NONCEBYTES 12
#define POLY1305_KEYBYTES   32
#define POLY1305_TAGBYTES   16

/* ChaCha20 stream: XOR `in` (or zeroes if in==NULL) with the keystream. */
KYBER_API void chacha20_xor_stream(const uint8_t key[CHACHA20_KEYBYTES], uint32_t counter,
                         const uint8_t nonce[CHACHA20_NONCEBYTES],
                         const uint8_t *in, uint8_t *out, size_t len);

/* Poly1305 one-time authenticator (RFC 8439). */
KYBER_API void poly1305_auth(uint8_t tag[POLY1305_TAGBYTES],
                   const uint8_t key[POLY1305_KEYBYTES],
                   const uint8_t *msg, size_t msglen);

/* AEAD seal (RFC 8439 ChaCha20-Poly1305). ct may alias msg. */
KYBER_API int chacha20poly1305_seal(const uint8_t key[CHACHA20_KEYBYTES],
                          const uint8_t nonce[CHACHA20_NONCEBYTES],
                          const uint8_t *aad, size_t aadlen,
                          const uint8_t *msg, size_t msglen,
                          uint8_t *ct, uint8_t tag[POLY1305_TAGBYTES]);

/* AEAD open. Returns 0 on verified success, -1 on authentication failure.
 * msg may alias ct. */
KYBER_API int chacha20poly1305_open(const uint8_t key[CHACHA20_KEYBYTES],
                         const uint8_t nonce[CHACHA20_NONCEBYTES],
                         const uint8_t *aad, size_t aadlen,
                         const uint8_t *ct, size_t ctlen,
                         const uint8_t tag[POLY1305_TAGBYTES], uint8_t *msg);

#endif
