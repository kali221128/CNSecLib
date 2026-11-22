/*
 * hybrid.h - ML-KEM + ChaCha20-Poly1305 hybrid encryption (FIPS 203 + RFC 8439)
 *
 * Combines a post-quantum ML-KEM key exchange with an AEAD data layer.
 * The plaintext is split into fixed 64 KiB chunks; every chunk is sealed
 * independently with its own nonce and an AAD binding the block index and
 * total block count (anti-reorder / anti-replay).
 *
 * Container layout (all multi-byte integers little-endian):
 *   [ KEM ciphertext          : kyber_ct_len(mode) bytes ]
 *   [ session nonce prefix    : 8 bytes                  ]
 *   [ total blocks            : uint32                  ]
 *   [ block records, each:                              ]
 *       [ nonce               : 12 bytes (prefix || idx) ]
 *       [ chunk ciphertext len: uint32                  ]
 *       [ Poly1305 tag        : 16 bytes               ]
 *       [ chunk ciphertext     : len bytes              ]
 */
#ifndef KYBER_HYBRID_H
#define KYBER_HYBRID_H

#include <stddef.h>
#include <stdint.h>
#include "kyber.h"
#include "kyber_export.h"

#define HYBRID_CHUNK        65536u   /* 64 KiB per AEAD chunk */
#define HYBRID_NONCE_PREFIX 8u
#define HYBRID_RECORD_OVERHEAD (12u + 4u + 16u)

/* Upper bound on the sealed container size for `plainlen` plaintext bytes. */
KYBER_API size_t hybrid_seal_capacity(kyber_mode mode, size_t plainlen);

/* Encapsulate to `pk` and encrypt `plain` into the container at `out`.
 * `out` must hold at least hybrid_seal_capacity(mode, plainlen) bytes.
 * Returns the container length on success, -1 on failure. */
KYBER_API int hybrid_seal(const uint8_t *pk, kyber_mode mode,
                const uint8_t *plain, size_t plainlen, uint8_t *out);

/* Decapsulate with `sk` and authenticate+decrypt the container at `container`.
 * Recovered plaintext is written to `out`; `out` must hold at least the
 * plaintext length (no upper bound is imposed here). Returns the plaintext
 * length on success, -1 on authentication or format failure. */
KYBER_API int hybrid_open(const uint8_t *sk, kyber_mode mode,
                const uint8_t *container, size_t containerlen, uint8_t *out);

#endif
