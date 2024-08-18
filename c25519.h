// https://www.dlbeer.co.nz/downloads/c25519-2017-10-05.zip
// MD5 sum: 2f19396f8becb44fe1cd5e40111e3ffb c25519-2017-10-05.zip
// Generated with $ cat src/f25519.h src/c25519.h src/ed25519.h
//      src/edsign.h src/fprime.h src/morph25519.h src/sha512.h
//      | sed 's/#include ".*"//g' > c25519.h

/* Arithmetic mod p = 2^255-19
 * Daniel Beer <dlbeer@gmail.com>, 8 Jan 2014
 *
 * This file is in the public domain.
 */

#ifndef F25519_H_
#define F25519_H_

#include <stdint.h>
#include <string.h>

/* Field elements are represented as little-endian byte strings. All
 * operations have timings which are independent of input data, so they
 * can be safely used for cryptography.
 *
 * Computation is performed on un-normalized elements. These are byte
 * strings which fall into the range 0 <= x < 2p. Use f25519_normalize()
 * to convert to a value 0 <= x < p.
 *
 * Elements received from the outside may greater even than 2p.
 * f25519_normalize() will correctly deal with these numbers too.
 */
#define F25519_SIZE  32

/* Identity constants */
extern const uint8_t f25519_zero[F25519_SIZE];
extern const uint8_t f25519_one[F25519_SIZE];

/* Load a small constant */
void f25519_load(uint8_t *x, uint32_t c);

/* Copy two points */
static inline void f25519_copy(uint8_t *x, const uint8_t *a)
{
	memcpy(x, a, F25519_SIZE);
}

/* Normalize a field point x < 2*p by subtracting p if necessary */
void f25519_normalize(uint8_t *x);

/* Compare two field points in constant time. Return one if equal, zero
 * otherwise. This should be performed only on normalized values.
 */
uint8_t f25519_eq(const uint8_t *x, const uint8_t *y);

/* Conditional copy. If condition == 0, then zero is copied to dst. If
 * condition == 1, then one is copied to dst. Any other value results in
 * undefined behaviour.
 */
void f25519_select(uint8_t *dst,
		   const uint8_t *zero, const uint8_t *one,
		   uint8_t condition);

/* Add/subtract two field points. The three pointers are not required to
 * be distinct.
 */
void f25519_add(uint8_t *r, const uint8_t *a, const uint8_t *b);
void f25519_sub(uint8_t *r, const uint8_t *a, const uint8_t *b);

/* Unary negation */
void f25519_neg(uint8_t *r, const uint8_t *a);

/* Multiply two field points. The __distinct variant is used when r is
 * known to be in a different location to a and b.
 */
void f25519_mul(uint8_t *r, const uint8_t *a, const uint8_t *b);
void f25519_mul__distinct(uint8_t *r, const uint8_t *a, const uint8_t *b);

/* Multiply a point by a small constant. The two pointers are not
 * required to be distinct.
 *
 * The constant must be less than 2^24.
 */
void f25519_mul_c(uint8_t *r, const uint8_t *a, uint32_t b);

/* Take the reciprocal of a field point. The __distinct variant is used
 * when r is known to be in a different location to x.
 */
void f25519_inv(uint8_t *r, const uint8_t *x);
void f25519_inv__distinct(uint8_t *r, const uint8_t *x);

/* Compute one of the square roots of the field element, if the element
 * is square. The other square is -r.
 *
 * If the input is not square, the returned value is a valid field
 * element, but not the correct answer. If you don't already know that
 * your element is square, you should square the return value and test.
 */
void f25519_sqrt(uint8_t *r, const uint8_t *x);

#endif
/* Curve25519 (Montgomery form)
 * Daniel Beer <dlbeer@gmail.com>, 18 Apr 2014
 *
 * This file is in the public domain.
 */

#ifndef C25519_H_
#define C25519_H_

#include <stdint.h>


/* Curve25519 has the equation over F(p = 2^255-19):
 *
 *    y^2 = x^3 + 486662x^2 + x
 *
 * 486662 = 4A+2, where A = 121665. This is a Montgomery curve.
 *
 * For more information, see:
 *
 *    Bernstein, D.J. (2006) "Curve25519: New Diffie-Hellman speed
 *    records". Document ID: 4230efdfa673480fc079449d90f322c0.
 */

/* This is the site of a Curve25519 exponent (private key) */
#define C25519_EXPONENT_SIZE  32

/* Having generated 32 random bytes, you should call this function to
 * finalize the generated key.
 */
static inline void c25519_prepare(uint8_t *key)
{
	key[0] &= 0xf8;
	key[31] &= 0x7f;
	key[31] |= 0x40;
}

/* X-coordinate of the base point */
extern const uint8_t c25519_base_x[F25519_SIZE];

/* X-coordinate scalar multiply: given the X-coordinate of q, return the
 * X-coordinate of e*q.
 *
 * result and q are field elements. e is an exponent.
 */
void c25519_smult(uint8_t *result, const uint8_t *q, const uint8_t *e);

#endif
/* Edwards curve operations
 * Daniel Beer <dlbeer@gmail.com>, 9 Jan 2014
 *
 * This file is in the public domain.
 */

#ifndef ED25519_H_
#define ED25519_H_



/* This is not the Ed25519 signature system. Rather, we're implementing
 * basic operations on the twisted Edwards curve over (Z mod 2^255-19):
 *
 *     -x^2 + y^2 = 1 - (121665/121666)x^2y^2
 *
 * With the positive-x base point y = 4/5.
 *
 * These functions will not leak secret data through timing.
 *
 * For more information, see:
 *
 *     Bernstein, D.J. & Lange, T. (2007) "Faster addition and doubling on
 *     elliptic curves". Document ID: 95616567a6ba20f575c5f25e7cebaf83.
 *
 *     Hisil, H. & Wong, K K. & Carter, G. & Dawson, E. (2008) "Twisted
 *     Edwards curves revisited". Advances in Cryptology, ASIACRYPT 2008,
 *     Vol. 5350, pp. 326-343.
 */

/* Projective coordinates */
struct ed25519_pt {
	uint8_t  x[F25519_SIZE];
	uint8_t  y[F25519_SIZE];
	uint8_t  t[F25519_SIZE];
	uint8_t  z[F25519_SIZE];
};

extern const struct ed25519_pt ed25519_base;
extern const struct ed25519_pt ed25519_neutral;

/* Convert between projective and affine coordinates (x/y in F25519) */
void ed25519_project(struct ed25519_pt *p,
		     const uint8_t *x, const uint8_t *y);

void ed25519_unproject(uint8_t *x, uint8_t *y,
		       const struct ed25519_pt *p);

/* Compress/uncompress points. try_unpack() will check that the
 * compressed point is on the curve, returning 1 if the unpacked point
 * is valid, and 0 otherwise.
 */
#define ED25519_PACK_SIZE  F25519_SIZE

void ed25519_pack(uint8_t *c, const uint8_t *x, const uint8_t *y);
uint8_t ed25519_try_unpack(uint8_t *x, uint8_t *y, const uint8_t *c);

/* Add, double and scalar multiply */
#define ED25519_EXPONENT_SIZE  32

/* Prepare an exponent by clamping appropriate bits */
static inline void ed25519_prepare(uint8_t *e)
{
	e[0] &= 0xf8;
	e[31] &= 0x7f;
	e[31] |= 0x40;
}

/* Order of the group generated by the base point */
static inline void ed25519_copy(struct ed25519_pt *dst,
				const struct ed25519_pt *src)
{
	memcpy(dst, src, sizeof(*dst));
}

void ed25519_add(struct ed25519_pt *r,
		 const struct ed25519_pt *a, const struct ed25519_pt *b);
void ed25519_double(struct ed25519_pt *r, const struct ed25519_pt *a);
void ed25519_smult(struct ed25519_pt *r, const struct ed25519_pt *a,
		   const uint8_t *e);

#endif
/* Edwards curve signature system
 * Daniel Beer <dlbeer@gmail.com>, 22 Apr 2014
 *
 * This file is in the public domain.
 */

#ifndef EDSIGN_H_
#define EDSIGN_H_

#include <stdint.h>
#include <stddef.h>

/* This is the Ed25519 signature system, as described in:
 *
 *     Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, Bo-Yin
 *     Yang. High-speed high-security signatures. Journal of Cryptographic
 *     Engineering 2 (2012), 77-89. Document ID:
 *     a1a62a2f76d23f65d622484ddd09caf8. URL:
 *     http://cr.yp.to/papers.html#ed25519. Date: 2011.09.26.
 *
 * The format and calculation of signatures is compatible with the
 * Ed25519 implementation in SUPERCOP. Note, however, that our secret
 * keys are half the size: we don't store a copy of the public key in
 * the secret key (we generate it on demand).
 */

/* Any string of 32 random bytes is a valid secret key. There is no
 * clamping of bits, because we don't use the key directly as an
 * exponent (the exponent is derived from part of a key expansion).
 */
#define EDSIGN_SECRET_KEY_SIZE  32

/* Given a secret key, produce the public key (a packed Edwards-curve
 * point).
 */
#define EDSIGN_PUBLIC_KEY_SIZE  32

void edsign_sec_to_pub(uint8_t *pub, const uint8_t *secret);

/* Produce a signature for a message. */
#define EDSIGN_SIGNATURE_SIZE  64

void edsign_sign(uint8_t *signature, const uint8_t *pub,
		 const uint8_t *secret,
		 const uint8_t *message, size_t len);

void edsign_sign_modified(uint8_t *signature, const uint8_t *pub,
		 const uint8_t *secret,
		 const uint8_t *message, size_t len);

/* Verify a message signature. Returns non-zero if ok. */
uint8_t edsign_verify(const uint8_t *signature, const uint8_t *pub,
		      const uint8_t *message, size_t len);

#endif
/* Arithmetic in prime fields
 * Daniel Beer <dlbeer@gmail.com>, 10 Jan 2014
 *
 * This file is in the public domain.
 */

#ifndef FPRIME_H_
#define FPRIME_H_

#include <stdint.h>
#include <string.h>

/* Maximum size of a field element (or a prime). Field elements are
 * always manipulated and stored in normalized form, with 0 <= x < p.
 * You can use normalize() to convert a denormalized bitstring to normal
 * form.
 *
 * Operations are constant with respect to the value of field elements,
 * but not with respect to the modulus.
 *
 * The modulus is a number p, such that 2p-1 fits in FPRIME_SIZE bytes.
 */
#define FPRIME_SIZE  32

/* Useful constants */
extern const uint8_t fprime_zero[FPRIME_SIZE];
extern const uint8_t fprime_one[FPRIME_SIZE];

/* Load a small constant */
void fprime_load(uint8_t *x, uint32_t c);

/* Load a large constant */
void fprime_from_bytes(uint8_t *x,
		       const uint8_t *in, size_t len,
		       const uint8_t *modulus);

/* Copy an element */
static inline void fprime_copy(uint8_t *x, const uint8_t *a)
{
	memcpy(x, a, FPRIME_SIZE);
}

/* Normalize a field element */
void fprime_normalize(uint8_t *x, const uint8_t *modulus);

/* Compare two field points in constant time. Return one if equal, zero
 * otherwise. This should be performed only on normalized values.
 */
uint8_t fprime_eq(const uint8_t *x, const uint8_t *y);

/* Conditional copy. If condition == 0, then zero is copied to dst. If
 * condition == 1, then one is copied to dst. Any other value results in
 * undefined behaviour.
 */
void fprime_select(uint8_t *dst,
		   const uint8_t *zero, const uint8_t *one,
		   uint8_t condition);

/* Add one value to another. The two pointers must be distinct. */
void fprime_add(uint8_t *r, const uint8_t *a, const uint8_t *modulus);
void fprime_sub(uint8_t *r, const uint8_t *a, const uint8_t *modulus);

/* Multiply two values to get a third. r must be distinct from a and b */
void fprime_mul(uint8_t *r, const uint8_t *a, const uint8_t *b,
		const uint8_t *modulus);

/* Compute multiplicative inverse. r must be distinct from a */
void fprime_inv(uint8_t *r, const uint8_t *a, const uint8_t *modulus);

#endif
/* Montgomery <-> Edwards isomorphism
 * Daniel Beer <dlbeer@gmail.com>, 18 Jan 2014
 *
 * This file is in the public domain.
 */

#ifndef MORPH25519_H_
#define MORPH25519_H_

#include <stdint.h>

/* Convert an Edwards Y to a Montgomery X (Edwards X is not used).
 * Resulting coordinate is normalized.
 */
void morph25519_e2m(uint8_t *montgomery_x, const uint8_t *edwards_y);

/* Return a parity bit for the Edwards X coordinate */
static inline int morph25519_eparity(const uint8_t *edwards_x)
{
	return edwards_x[0] & 1;
}

/* Convert a Montgomery X and a parity bit to an Edwards X/Y. Returns
 * non-zero if successful.
 */
uint8_t morph25519_m2e(uint8_t *ex, uint8_t *ey,
		       const uint8_t *mx, int parity);

void morph25519_mx2ey(uint8_t *ey, const uint8_t *mx);

#endif
/* SHA512
 * Daniel Beer <dlbeer@gmail.com>, 22 Apr 2014
 *
 * This file is in the public domain.
 */

#ifndef SHA512_H_
#define SHA512_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* SHA512 state. State is updated as data is fed in, and then the final
 * hash can be read out in slices.
 *
 * Data is fed in as a sequence of full blocks terminated by a single
 * partial block.
 */
struct sha512_state {
	uint64_t  h[8];
};

/* Initial state */
extern const struct sha512_state sha512_initial_state;

/* Set up a new context */
static inline void sha512_init(struct sha512_state *s)
{
	memcpy(s, &sha512_initial_state, sizeof(*s));
}

/* Feed a full block in */
#define SHA512_BLOCK_SIZE  128

void sha512_block(struct sha512_state *s, const uint8_t *blk);

/* Feed the last partial block in. The total stream size must be
 * specified. The size of the block given is assumed to be (total_size %
 * SHA512_BLOCK_SIZE). This might be zero, but you still need to call
 * this function to terminate the stream.
 */
void sha512_final(struct sha512_state *s, const uint8_t *blk,
		  size_t total_size);

/* Fetch a slice of the hash result. */
#define SHA512_HASH_SIZE  64

void sha512_get(const struct sha512_state *s, uint8_t *hash,
		unsigned int offset, unsigned int len);

#endif
