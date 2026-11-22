/*
 * kyber.h - ML-KEM (CRYSTALS-Kyber, FIPS 203) pure C KEM
 *
 * Supports all three parameter sets: ML-KEM-512 / 768 / 1024.
 * Byte-level compatible with the standard ML-KEM decapsulation/encapsulation.
 *
 * Standard byte lengths:
 *   ML-KEM-512  : pk  800 B, sk 1632 B, ct  768 B, ss 32 B
 *   ML-KEM-768  : pk 1184 B, sk 2400 B, ct 1088 B, ss 32 B
 *   ML-KEM-1024 : pk 1568 B, sk 3168 B, ct 1568 B, ss 32 B
 */
#ifndef KYBER_H
#define KYBER_H

#include <stddef.h>
#include <stdint.h>
#include "kyber_export.h"

typedef enum {
    KYBER_512 = 0,
    KYBER_768 = 1,
    KYBER_1024 = 2
} kyber_mode;

/* Buffer lengths for the selected parameter set. */
KYBER_API size_t kyber_pk_len(kyber_mode mode);
KYBER_API size_t kyber_sk_len(kyber_mode mode);
KYBER_API size_t kyber_ct_len(kyber_mode mode);
KYBER_API size_t kyber_ss_len(void); /* always 32 */

/* Generate a key pair using the system CSPRNG. Returns 0 on success. */
KYBER_API int kyber_keypair(uint8_t *pk, uint8_t *sk, kyber_mode mode);

/* Deterministic key pair from a 64-byte coin string (d || z). For tests /
 * interop with reference vectors. Returns 0 on success. */
KYBER_API int kyber_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t coins[64],
                         kyber_mode mode);

/* Encapsulate: produce ciphertext `ct` and shared secret `ss` (32 B) for the
 * public key `pk`. Returns 0 on success. */
KYBER_API int kyber_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, kyber_mode mode);

/* Deterministic encapsulation from a 32-byte coin string. For tests / interop. */
KYBER_API int kyber_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                        const uint8_t coins[32], kyber_mode mode);

/* Decapsulate: recover the shared secret `ss` (32 B) from `ct` and secret
 * key `sk`. On invalid ciphertext, ss holds a pseudo-random value. */
KYBER_API int kyber_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk,
                 kyber_mode mode);

#endif
