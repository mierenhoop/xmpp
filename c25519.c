// https://www.dlbeer.co.nz/downloads/c25519-2017-10-05.zip
// MD5 sum: 2f19396f8becb44fe1cd5e40111e3ffb c25519-2017-10-05.zip
// Generated with $ cat src/*.c | sed 's/#include ".*"//g' > c25519.c

// Modification: edsign_sign_modified is added which is a replacement
// for libsignal-protocol-c's crypto_sign_modifed. edsign_sign_modified
// is in the public domain.

/* Curve25519 (Montgomery form)
 * Daniel Beer <dlbeer@gmail.com>, 18 Apr 2014
 *
 * This file is in the public domain.
 */

#include "c25519.h"

const uint8_t c25519_base_x[F25519_SIZE] = {9};

/* Double an X-coordinate */
static void xc_double(uint8_t *x3, uint8_t *z3,
		      const uint8_t *x1, const uint8_t *z1)
{
	/* Explicit formulas database: dbl-1987-m
	 *
	 * source 1987 Montgomery "Speeding the Pollard and elliptic
	 *   curve methods of factorization", page 261, fourth display
	 * compute X3 = (X1^2-Z1^2)^2
	 * compute Z3 = 4 X1 Z1 (X1^2 + a X1 Z1 + Z1^2)
	 */
	uint8_t x1sq[F25519_SIZE];
	uint8_t z1sq[F25519_SIZE];
	uint8_t x1z1[F25519_SIZE];
	uint8_t a[F25519_SIZE];

	f25519_mul__distinct(x1sq, x1, x1);
	f25519_mul__distinct(z1sq, z1, z1);
	f25519_mul__distinct(x1z1, x1, z1);

	f25519_sub(a, x1sq, z1sq);
	f25519_mul__distinct(x3, a, a);

	f25519_mul_c(a, x1z1, 486662);
	f25519_add(a, x1sq, a);
	f25519_add(a, z1sq, a);
	f25519_mul__distinct(x1sq, x1z1, a);
	f25519_mul_c(z3, x1sq, 4);
}

/* Differential addition */
static void xc_diffadd(uint8_t *x5, uint8_t *z5,
		       const uint8_t *x1, const uint8_t *z1,
		       const uint8_t *x2, const uint8_t *z2,
		       const uint8_t *x3, const uint8_t *z3)
{
	/* Explicit formulas database: dbl-1987-m3
	 *
	 * source 1987 Montgomery "Speeding the Pollard and elliptic curve
	 *   methods of factorization", page 261, fifth display, plus
	 *   common-subexpression elimination
	 * compute A = X2+Z2
	 * compute B = X2-Z2
	 * compute C = X3+Z3
	 * compute D = X3-Z3
	 * compute DA = D A
	 * compute CB = C B
	 * compute X5 = Z1(DA+CB)^2
	 * compute Z5 = X1(DA-CB)^2
	 */
	uint8_t da[F25519_SIZE];
	uint8_t cb[F25519_SIZE];
	uint8_t a[F25519_SIZE];
	uint8_t b[F25519_SIZE];

	f25519_add(a, x2, z2);
	f25519_sub(b, x3, z3); /* D */
	f25519_mul__distinct(da, a, b);

	f25519_sub(b, x2, z2);
	f25519_add(a, x3, z3); /* C */
	f25519_mul__distinct(cb, a, b);

	f25519_add(a, da, cb);
	f25519_mul__distinct(b, a, a);
	f25519_mul__distinct(x5, z1, b);

	f25519_sub(a, da, cb);
	f25519_mul__distinct(b, a, a);
	f25519_mul__distinct(z5, x1, b);
}

void c25519_smult(uint8_t *result, const uint8_t *q, const uint8_t *e)
{
	/* Current point: P_m */
	uint8_t xm[F25519_SIZE];
	uint8_t zm[F25519_SIZE] = {1};

	/* Predecessor: P_(m-1) */
	uint8_t xm1[F25519_SIZE] = {1};
	uint8_t zm1[F25519_SIZE] = {0};

	int i;

	/* Note: bit 254 is assumed to be 1 */
	f25519_copy(xm, q);

	for (i = 253; i >= 0; i--) {
		const int bit = (e[i >> 3] >> (i & 7)) & 1;
		uint8_t xms[F25519_SIZE];
		uint8_t zms[F25519_SIZE];

		/* From P_m and P_(m-1), compute P_(2m) and P_(2m-1) */
		xc_diffadd(xm1, zm1, q, f25519_one, xm, zm, xm1, zm1);
		xc_double(xm, zm, xm, zm);

		/* Compute P_(2m+1) */
		xc_diffadd(xms, zms, xm1, zm1, xm, zm, q, f25519_one);

		/* Select:
		 *   bit = 1 --> (P_(2m+1), P_(2m))
		 *   bit = 0 --> (P_(2m), P_(2m-1))
		 */
		f25519_select(xm1, xm1, xm, bit);
		f25519_select(zm1, zm1, zm, bit);
		f25519_select(xm, xm, xms, bit);
		f25519_select(zm, zm, zms, bit);
	}

	/* Freeze out of projective coordinates */
	f25519_inv__distinct(zm1, zm);
	f25519_mul__distinct(result, zm1, xm);
	f25519_normalize(result);
}
/* Edwards curve operations
 * Daniel Beer <dlbeer@gmail.com>, 9 Jan 2014
 *
 * This file is in the public domain.
 */



/* Base point is (numbers wrapped):
 *
 *     x = 151122213495354007725011514095885315114
 *         54012693041857206046113283949847762202
 *     y = 463168356949264781694283940034751631413
 *         07993866256225615783033603165251855960
 *
 * y is derived by transforming the original Montgomery base (u=9). x
 * is the corresponding positive coordinate for the new curve equation.
 * t is x*y.
 */
const struct ed25519_pt ed25519_base = {
	.x = {
		0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
		0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
		0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
		0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21
	},
	.y = {
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
	},
	.t = {
		0xa3, 0xdd, 0xb7, 0xa5, 0xb3, 0x8a, 0xde, 0x6d,
		0xf5, 0x52, 0x51, 0x77, 0x80, 0x9f, 0xf0, 0x20,
		0x7d, 0xe3, 0xab, 0x64, 0x8e, 0x4e, 0xea, 0x66,
		0x65, 0x76, 0x8b, 0xd7, 0x0f, 0x5f, 0x87, 0x67
	},
	.z = {1, 0}
};

const struct ed25519_pt ed25519_neutral = {
	.x = {0},
	.y = {1, 0},
	.t = {0},
	.z = {1, 0}
};

/* Conversion to and from projective coordinates */
void ed25519_project(struct ed25519_pt *p,
		     const uint8_t *x, const uint8_t *y)
{
	f25519_copy(p->x, x);
	f25519_copy(p->y, y);
	f25519_load(p->z, 1);
	f25519_mul__distinct(p->t, x, y);
}

void ed25519_unproject(uint8_t *x, uint8_t *y,
		       const struct ed25519_pt *p)
{
	uint8_t z1[F25519_SIZE];

	f25519_inv__distinct(z1, p->z);
	f25519_mul__distinct(x, p->x, z1);
	f25519_mul__distinct(y, p->y, z1);

	f25519_normalize(x);
	f25519_normalize(y);
}

/* Compress/uncompress points. We compress points by storing the x
 * coordinate and the parity of the y coordinate.
 *
 * Rearranging the curve equation, we obtain explicit formulae for the
 * coordinates:
 *
 *     x = sqrt((y^2-1) / (1+dy^2))
 *     y = sqrt((x^2+1) / (1-dx^2))
 *
 * Where d = (-121665/121666), or:
 *
 *     d = 370957059346694393431380835087545651895
 *         42113879843219016388785533085940283555
 */

static const uint8_t ed25519_d[F25519_SIZE] = {
	0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
	0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
	0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
	0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};

void ed25519_pack(uint8_t *c, const uint8_t *x, const uint8_t *y)
{
	uint8_t tmp[F25519_SIZE];
	uint8_t parity;

	f25519_copy(tmp, x);
	f25519_normalize(tmp);
	parity = (tmp[0] & 1) << 7;

	f25519_copy(c, y);
	f25519_normalize(c);
	c[31] |= parity;
}

uint8_t ed25519_try_unpack(uint8_t *x, uint8_t *y, const uint8_t *comp)
{
	const int parity = comp[31] >> 7;
	uint8_t a[F25519_SIZE];
	uint8_t b[F25519_SIZE];
	uint8_t c[F25519_SIZE];

	/* Unpack y */
	f25519_copy(y, comp);
	y[31] &= 127;

	/* Compute c = y^2 */
	f25519_mul__distinct(c, y, y);

	/* Compute b = (1+dy^2)^-1 */
	f25519_mul__distinct(b, c, ed25519_d);
	f25519_add(a, b, f25519_one);
	f25519_inv__distinct(b, a);

	/* Compute a = y^2-1 */
	f25519_sub(a, c, f25519_one);

	/* Compute c = a*b = (y^2-1)/(1-dy^2) */
	f25519_mul__distinct(c, a, b);

	/* Compute a, b = +/-sqrt(c), if c is square */
	f25519_sqrt(a, c);
	f25519_neg(b, a);

	/* Select one of them, based on the compressed parity bit */
	f25519_select(x, a, b, (a[0] ^ parity) & 1);

	/* Verify that x^2 = c */
	f25519_mul__distinct(a, x, x);
	f25519_normalize(a);
	f25519_normalize(c);

	return f25519_eq(a, c);
}

/* k = 2d */
static const uint8_t ed25519_k[F25519_SIZE] = {
	0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
	0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
	0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19,
	0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24
};

void ed25519_add(struct ed25519_pt *r,
		 const struct ed25519_pt *p1, const struct ed25519_pt *p2)
{
	/* Explicit formulas database: add-2008-hwcd-3
	 *
	 * source 2008 Hisil--Wong--Carter--Dawson,
	 *     http://eprint.iacr.org/2008/522, Section 3.1
	 * appliesto extended-1
	 * parameter k
	 * assume k = 2 d
	 * compute A = (Y1-X1)(Y2-X2)
	 * compute B = (Y1+X1)(Y2+X2)
	 * compute C = T1 k T2
	 * compute D = Z1 2 Z2
	 * compute E = B - A
	 * compute F = D - C
	 * compute G = D + C
	 * compute H = B + A
	 * compute X3 = E F
	 * compute Y3 = G H
	 * compute T3 = E H
	 * compute Z3 = F G
	 */
	uint8_t a[F25519_SIZE];
	uint8_t b[F25519_SIZE];
	uint8_t c[F25519_SIZE];
	uint8_t d[F25519_SIZE];
	uint8_t e[F25519_SIZE];
	uint8_t f[F25519_SIZE];
	uint8_t g[F25519_SIZE];
	uint8_t h[F25519_SIZE];

	/* A = (Y1-X1)(Y2-X2) */
	f25519_sub(c, p1->y, p1->x);
	f25519_sub(d, p2->y, p2->x);
	f25519_mul__distinct(a, c, d);

	/* B = (Y1+X1)(Y2+X2) */
	f25519_add(c, p1->y, p1->x);
	f25519_add(d, p2->y, p2->x);
	f25519_mul__distinct(b, c, d);

	/* C = T1 k T2 */
	f25519_mul__distinct(d, p1->t, p2->t);
	f25519_mul__distinct(c, d, ed25519_k);

	/* D = Z1 2 Z2 */
	f25519_mul__distinct(d, p1->z, p2->z);
	f25519_add(d, d, d);

	/* E = B - A */
	f25519_sub(e, b, a);

	/* F = D - C */
	f25519_sub(f, d, c);

	/* G = D + C */
	f25519_add(g, d, c);

	/* H = B + A */
	f25519_add(h, b, a);

	/* X3 = E F */
	f25519_mul__distinct(r->x, e, f);

	/* Y3 = G H */
	f25519_mul__distinct(r->y, g, h);

	/* T3 = E H */
	f25519_mul__distinct(r->t, e, h);

	/* Z3 = F G */
	f25519_mul__distinct(r->z, f, g);
}

void ed25519_double(struct ed25519_pt *r, const struct ed25519_pt *p)
{
	/* Explicit formulas database: dbl-2008-hwcd
	 *
	 * source 2008 Hisil--Wong--Carter--Dawson,
	 *     http://eprint.iacr.org/2008/522, Section 3.3
	 * compute A = X1^2
	 * compute B = Y1^2
	 * compute C = 2 Z1^2
	 * compute D = a A
	 * compute E = (X1+Y1)^2-A-B
	 * compute G = D + B
	 * compute F = G - C
	 * compute H = D - B
	 * compute X3 = E F
	 * compute Y3 = G H
	 * compute T3 = E H
	 * compute Z3 = F G
	 */
	uint8_t a[F25519_SIZE];
	uint8_t b[F25519_SIZE];
	uint8_t c[F25519_SIZE];
	uint8_t e[F25519_SIZE];
	uint8_t f[F25519_SIZE];
	uint8_t g[F25519_SIZE];
	uint8_t h[F25519_SIZE];

	/* A = X1^2 */
	f25519_mul__distinct(a, p->x, p->x);

	/* B = Y1^2 */
	f25519_mul__distinct(b, p->y, p->y);

	/* C = 2 Z1^2 */
	f25519_mul__distinct(c, p->z, p->z);
	f25519_add(c, c, c);

	/* D = a A (alter sign) */
	/* E = (X1+Y1)^2-A-B */
	f25519_add(f, p->x, p->y);
	f25519_mul__distinct(e, f, f);
	f25519_sub(e, e, a);
	f25519_sub(e, e, b);

	/* G = D + B */
	f25519_sub(g, b, a);

	/* F = G - C */
	f25519_sub(f, g, c);

	/* H = D - B */
	f25519_neg(h, b);
	f25519_sub(h, h, a);

	/* X3 = E F */
	f25519_mul__distinct(r->x, e, f);

	/* Y3 = G H */
	f25519_mul__distinct(r->y, g, h);

	/* T3 = E H */
	f25519_mul__distinct(r->t, e, h);

	/* Z3 = F G */
	f25519_mul__distinct(r->z, f, g);
}

void ed25519_smult(struct ed25519_pt *r_out, const struct ed25519_pt *p,
		   const uint8_t *e)
{
	struct ed25519_pt r;
	int i;

	ed25519_copy(&r, &ed25519_neutral);

	for (i = 255; i >= 0; i--) {
		const uint8_t bit = (e[i >> 3] >> (i & 7)) & 1;
		struct ed25519_pt s;

		ed25519_double(&r, &r);
		ed25519_add(&s, &r, p);

		f25519_select(r.x, r.x, s.x, bit);
		f25519_select(r.y, r.y, s.y, bit);
		f25519_select(r.z, r.z, s.z, bit);
		f25519_select(r.t, r.t, s.t, bit);
	}

	ed25519_copy(r_out, &r);
}
/* Edwards curve signature system
 * Daniel Beer <dlbeer@gmail.com>, 22 Apr 2014
 *
 * This file is in the public domain.
 */






#define EXPANDED_SIZE  64

static const uint8_t ed25519_order[FPRIME_SIZE] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void expand_key(uint8_t *expanded, const uint8_t *secret)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_final(&s, secret, EDSIGN_SECRET_KEY_SIZE);
	sha512_get(&s, expanded, 0, EXPANDED_SIZE);
	ed25519_prepare(expanded);
}

static uint8_t upp(struct ed25519_pt *p, const uint8_t *packed)
{
	uint8_t x[F25519_SIZE];
	uint8_t y[F25519_SIZE];
	uint8_t ok = ed25519_try_unpack(x, y, packed);

	ed25519_project(p, x, y);
	return ok;
}

static void pp(uint8_t *packed, const struct ed25519_pt *p)
{
	uint8_t x[F25519_SIZE];
	uint8_t y[F25519_SIZE];

	ed25519_unproject(x, y, p);
	ed25519_pack(packed, x, y);
}

static void sm_pack(uint8_t *r, const uint8_t *k)
{
	struct ed25519_pt p;

	ed25519_smult(&p, &ed25519_base, k);
	pp(r, &p);
}

void edsign_sec_to_pub(uint8_t *pub, const uint8_t *secret)
{
	uint8_t expanded[EXPANDED_SIZE];

	expand_key(expanded, secret);
	sm_pack(pub, expanded);
}

static void hash_with_prefix(uint8_t *out_fp,
			     uint8_t *init_block, unsigned int prefix_size,
			     const uint8_t *message, size_t len)
{
	struct sha512_state s;

	sha512_init(&s);

	if (len < SHA512_BLOCK_SIZE && len + prefix_size < SHA512_BLOCK_SIZE) {
		memcpy(init_block + prefix_size, message, len);
		sha512_final(&s, init_block, len + prefix_size);
	} else {
		size_t i;

		memcpy(init_block + prefix_size, message,
		       SHA512_BLOCK_SIZE - prefix_size);
		sha512_block(&s, init_block);

		for (i = SHA512_BLOCK_SIZE - prefix_size;
		     i + SHA512_BLOCK_SIZE <= len;
		     i += SHA512_BLOCK_SIZE)
			sha512_block(&s, message + i);

		sha512_final(&s, message + i, len + prefix_size);
	}

	sha512_get(&s, init_block, 0, SHA512_HASH_SIZE);
	fprime_from_bytes(out_fp, init_block, SHA512_HASH_SIZE, ed25519_order);
}

static void generate_k(uint8_t *k, const uint8_t *kgen_key,
		       const uint8_t *message, size_t len)
{
	uint8_t block[SHA512_BLOCK_SIZE];

	memcpy(block, kgen_key, 32);
	hash_with_prefix(k, block, 32, message, len);
}

static void hash_message(uint8_t *z, const uint8_t *r, const uint8_t *a,
			 const uint8_t *m, size_t len)
{
	uint8_t block[SHA512_BLOCK_SIZE];

	memcpy(block, r, 32);
	memcpy(block + 32, a, 32);
	hash_with_prefix(z, block, 64, m, len);
}

void edsign_sign(uint8_t *signature, const uint8_t *pub,
		 const uint8_t *secret,
		 const uint8_t *message, size_t len)
{
	uint8_t expanded[EXPANDED_SIZE];
	uint8_t e[FPRIME_SIZE];
	uint8_t s[FPRIME_SIZE];
	uint8_t k[FPRIME_SIZE];
	uint8_t z[FPRIME_SIZE];

	expand_key(expanded, secret);

	/* Generate k and R = kB */
	generate_k(k, expanded + 32, message, len);
	sm_pack(signature, k);

	/* Compute z = H(R, A, M) */
	hash_message(z, signature, pub, message, len);

	/* Obtain e */
	fprime_from_bytes(e, expanded, 32, ed25519_order);

	/* Compute s = ze + k */
	fprime_mul(s, z, e, ed25519_order);
	fprime_add(s, k, ed25519_order);
	memcpy(signature + 32, s, 32);
}

// We expect message to be suffixed with 64 bytes of random data, while len contains the original message length.
void edsign_sign_modified(uint8_t *signature, const uint8_t *pub,
		 const uint8_t *secret,
		 const uint8_t *message, size_t len)
{
	uint8_t e[FPRIME_SIZE];
	uint8_t s[FPRIME_SIZE];
	uint8_t k[FPRIME_SIZE];
	uint8_t z[FPRIME_SIZE];

	signature[0] = 0xfe;
	memset(signature + 1, 0xff, 31);
	memcpy(signature + 32, secret, 32);

	/* Generate k and R = kB */
	// This is a modified version of generate_k inlined.
	{
		uint8_t block[SHA512_BLOCK_SIZE];

		memcpy(block, signature, 64);
		hash_with_prefix(k, block, 64, message, len + 64);
	}
	sm_pack(signature, k);

	/* Compute z = H(R, A, M) */
	hash_message(z, signature, pub, message, len);

	fprime_from_bytes(e, secret, 32, ed25519_order);

	/* Compute s = ze + k */
	fprime_mul(s, z, e, ed25519_order);
	fprime_add(s, k, ed25519_order);
	memcpy(signature + 32, s, 32);
}

uint8_t edsign_verify(const uint8_t *signature, const uint8_t *pub,
		      const uint8_t *message, size_t len)
{
	struct ed25519_pt p;
	struct ed25519_pt q;
	uint8_t lhs[F25519_SIZE];
	uint8_t rhs[F25519_SIZE];
	uint8_t z[FPRIME_SIZE];
	uint8_t ok = 1;

	/* Compute z = H(R, A, M) */
	hash_message(z, signature, pub, message, len);

	/* sB = (ze + k)B = ... */
	sm_pack(lhs, signature + 32);

	/* ... = zA + R */
	ok &= upp(&p, pub);
	ed25519_smult(&p, &p, z);
	ok &= upp(&q, signature);
	ed25519_add(&p, &p, &q);
	pp(rhs, &p);

	/* Equal? */
	return ok & f25519_eq(lhs, rhs);
}
/* Arithmetic mod p = 2^255-19
 * Daniel Beer <dlbeer@gmail.com>, 5 Jan 2014
 *
 * This file is in the public domain.
 */



const uint8_t f25519_zero[F25519_SIZE] = {0};
const uint8_t f25519_one[F25519_SIZE] = {1};

void f25519_load(uint8_t *x, uint32_t c)
{
	unsigned int i;

	for (i = 0; i < sizeof(c); i++) {
		x[i] = c;
		c >>= 8;
	}

	for (; i < F25519_SIZE; i++)
		x[i] = 0;
}

void f25519_normalize(uint8_t *x)
{
	uint8_t minusp[F25519_SIZE];
	uint16_t c;
	int i;

	/* Reduce using 2^255 = 19 mod p */
	c = (x[31] >> 7) * 19;
	x[31] &= 127;

	for (i = 0; i < F25519_SIZE; i++) {
		c += x[i];
		x[i] = c;
		c >>= 8;
	}

	/* The number is now less than 2^255 + 18, and therefore less than
	 * 2p. Try subtracting p, and conditionally load the subtracted
	 * value if underflow did not occur.
	 */
	c = 19;

	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += x[i];
		minusp[i] = c;
		c >>= 8;
	}

	c += ((uint16_t)x[i]) - 128;
	minusp[31] = c;

	/* Load x-p if no underflow */
	f25519_select(x, minusp, x, (c >> 15) & 1);
}

uint8_t f25519_eq(const uint8_t *x, const uint8_t *y)
{
	uint8_t sum = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++)
		sum |= x[i] ^ y[i];

	sum |= (sum >> 4);
	sum |= (sum >> 2);
	sum |= (sum >> 1);

	return (sum ^ 1) & 1;
}

void f25519_select(uint8_t *dst,
		   const uint8_t *zero, const uint8_t *one,
		   uint8_t condition)
{
	const uint8_t mask = -condition;
	int i;

	for (i = 0; i < F25519_SIZE; i++)
		dst[i] = zero[i] ^ (mask & (one[i] ^ zero[i]));
}

void f25519_add(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint16_t c = 0;
	int i;

	/* Add */
	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += ((uint16_t)a[i]) + ((uint16_t)b[i]);
		r[i] = c;
	}

	/* Reduce with 2^255 = 19 mod p */
	r[31] &= 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_sub(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint32_t c = 0;
	int i;

	/* Calculate a + 2p - b, to avoid underflow */
	c = 218;
	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += 65280 + ((uint32_t)a[i]) - ((uint32_t)b[i]);
		r[i] = c;
		c >>= 8;
	}

	c += ((uint32_t)a[31]) - ((uint32_t)b[31]);
	r[31] = c & 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_neg(uint8_t *r, const uint8_t *a)
{
	uint32_t c = 0;
	int i;

	/* Calculate 2p - a, to avoid underflow */
	c = 218;
	for (i = 0; i + 1 < F25519_SIZE; i++) {
		c += 65280 - ((uint32_t)a[i]);
		r[i] = c;
		c >>= 8;
	}

	c -= ((uint32_t)a[31]);
	r[31] = c & 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_mul__distinct(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint32_t c = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++) {
		int j;

		c >>= 8;
		for (j = 0; j <= i; j++)
			c += ((uint32_t)a[j]) * ((uint32_t)b[i - j]);

		for (; j < F25519_SIZE; j++)
			c += ((uint32_t)a[j]) *
			     ((uint32_t)b[i + F25519_SIZE - j]) * 38;

		r[i] = c;
	}

	r[31] &= 127;
	c = (c >> 7) * 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_mul(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint8_t tmp[F25519_SIZE];

	f25519_mul__distinct(tmp, a, b);
	f25519_copy(r, tmp);
}

void f25519_mul_c(uint8_t *r, const uint8_t *a, uint32_t b)
{
	uint32_t c = 0;
	int i;

	for (i = 0; i < F25519_SIZE; i++) {
		c >>= 8;
		c += b * ((uint32_t)a[i]);
		r[i] = c;
	}

	r[31] &= 127;
	c >>= 7;
	c *= 19;

	for (i = 0; i < F25519_SIZE; i++) {
		c += r[i];
		r[i] = c;
		c >>= 8;
	}
}

void f25519_inv__distinct(uint8_t *r, const uint8_t *x)
{
	uint8_t s[F25519_SIZE];
	int i;

	/* This is a prime field, so by Fermat's little theorem:
	 *
	 *     x^(p-1) = 1 mod p
	 *
	 * Therefore, raise to (p-2) = 2^255-21 to get a multiplicative
	 * inverse.
	 *
	 * This is a 255-bit binary number with the digits:
	 *
	 *     11111111... 01011
	 *
	 * We compute the result by the usual binary chain, but
	 * alternate between keeping the accumulator in r and s, so as
	 * to avoid copying temporaries.
	 */

	/* 1 1 */
	f25519_mul__distinct(s, x, x);
	f25519_mul__distinct(r, s, x);

	/* 1 x 248 */
	for (i = 0; i < 248; i++) {
		f25519_mul__distinct(s, r, r);
		f25519_mul__distinct(r, s, x);
	}

	/* 0 */
	f25519_mul__distinct(s, r, r);

	/* 1 */
	f25519_mul__distinct(r, s, s);
	f25519_mul__distinct(s, r, x);

	/* 0 */
	f25519_mul__distinct(r, s, s);

	/* 1 */
	f25519_mul__distinct(s, r, r);
	f25519_mul__distinct(r, s, x);

	/* 1 */
	f25519_mul__distinct(s, r, r);
	f25519_mul__distinct(r, s, x);
}

void f25519_inv(uint8_t *r, const uint8_t *x)
{
	uint8_t tmp[F25519_SIZE];

	f25519_inv__distinct(tmp, x);
	f25519_copy(r, tmp);
}

/* Raise x to the power of (p-5)/8 = 2^252-3, using s for temporary
 * storage.
 */
static void exp2523(uint8_t *r, const uint8_t *x, uint8_t *s)
{
	int i;

	/* This number is a 252-bit number with the binary expansion:
	 *
	 *     111111... 01
	 */

	/* 1 1 */
	f25519_mul__distinct(r, x, x);
	f25519_mul__distinct(s, r, x);

	/* 1 x 248 */
	for (i = 0; i < 248; i++) {
		f25519_mul__distinct(r, s, s);
		f25519_mul__distinct(s, r, x);
	}

	/* 0 */
	f25519_mul__distinct(r, s, s);

	/* 1 */
	f25519_mul__distinct(s, r, r);
	f25519_mul__distinct(r, s, x);
}

void f25519_sqrt(uint8_t *r, const uint8_t *a)
{
	uint8_t v[F25519_SIZE];
	uint8_t i[F25519_SIZE];
	uint8_t x[F25519_SIZE];
	uint8_t y[F25519_SIZE];

	/* v = (2a)^((p-5)/8) [x = 2a] */
	f25519_mul_c(x, a, 2);
	exp2523(v, x, y);

	/* i = 2av^2 - 1 */
	f25519_mul__distinct(y, v, v);
	f25519_mul__distinct(i, x, y);
	f25519_load(y, 1);
	f25519_sub(i, i, y);

	/* r = avi */
	f25519_mul__distinct(x, v, a);
	f25519_mul__distinct(r, x, i);
}
/* Arithmetic in prime fields
 * Daniel Beer <dlbeer@gmail.com>, 10 Jan 2014
 *
 * This file is in the public domain.
 */



const uint8_t fprime_zero[FPRIME_SIZE] = {0};
const uint8_t fprime_one[FPRIME_SIZE] = {1};

static void raw_add(uint8_t *x, const uint8_t *p)
{
	uint16_t c = 0;
	int i;

	for (i = 0; i < FPRIME_SIZE; i++) {
		c += ((uint16_t)x[i]) + ((uint16_t)p[i]);
		x[i] = c;
		c >>= 8;
	}
}

static void raw_try_sub(uint8_t *x, const uint8_t *p)
{
	uint8_t minusp[FPRIME_SIZE];
	uint16_t c = 0;
	int i;

	for (i = 0; i < FPRIME_SIZE; i++) {
		c = ((uint16_t)x[i]) - ((uint16_t)p[i]) - c;
		minusp[i] = c;
		c = (c >> 8) & 1;
	}

	fprime_select(x, minusp, x, c);
}

/* Warning: this function is variable-time */
static int prime_msb(const uint8_t *p)
{
	int i;
	uint8_t x;

	for (i = FPRIME_SIZE - 1; i >= 0; i--)
		if (p[i])
			break;

	x = p[i];
	i <<= 3;

	while (x) {
		x >>= 1;
		i++;
	}

	return i - 1;
}

/* Warning: this function may be variable-time in the argument n */
static void shift_n_bits(uint8_t *x, int n)
{
	uint16_t c = 0;
	int i;

	for (i = 0; i < FPRIME_SIZE; i++) {
		c |= ((uint16_t)x[i]) << n;
		x[i] = c;
		c >>= 8;
	}
}

void fprime_load(uint8_t *x, uint32_t c)
{
	unsigned int i;

	for (i = 0; i < sizeof(c); i++) {
		x[i] = c;
		c >>= 8;
	}

	for (; i < FPRIME_SIZE; i++)
		x[i] = 0;
}

static inline int min_int(int a, int b)
{
	return a < b ? a : b;
}

void fprime_from_bytes(uint8_t *n,
		       const uint8_t *x, size_t len,
		       const uint8_t *modulus)
{
	const int preload_total = min_int(prime_msb(modulus) - 1, len << 3);
	const int preload_bytes = preload_total >> 3;
	const int preload_bits = preload_total & 7;
	const int rbits = (len << 3) - preload_total;
	int i;

	memset(n, 0, FPRIME_SIZE);

	for (i = 0; i < preload_bytes; i++)
		n[i] = x[len - preload_bytes + i];

	if (preload_bits) {
		shift_n_bits(n, preload_bits);
		n[0] |= x[len - preload_bytes - 1] >> (8 - preload_bits);
	}

	for (i = rbits - 1; i >= 0; i--) {
		const uint8_t bit = (x[i >> 3] >> (i & 7)) & 1;

		shift_n_bits(n, 1);
		n[0] |= bit;
		raw_try_sub(n, modulus);
	}
}

void fprime_normalize(uint8_t *x, const uint8_t *modulus)
{
	uint8_t n[FPRIME_SIZE];

	fprime_from_bytes(n, x, FPRIME_SIZE, modulus);
	fprime_copy(x, n);
}

uint8_t fprime_eq(const uint8_t *x, const uint8_t *y)
{
	uint8_t sum = 0;
	int i;

	for (i = 0; i < FPRIME_SIZE; i++)
		sum |= x[i] ^ y[i];

	sum |= (sum >> 4);
	sum |= (sum >> 2);
	sum |= (sum >> 1);

	return (sum ^ 1) & 1;
}

void fprime_select(uint8_t *dst,
		   const uint8_t *zero, const uint8_t *one,
		   uint8_t condition)
{
	const uint8_t mask = -condition;
	int i;

	for (i = 0; i < FPRIME_SIZE; i++)
		dst[i] = zero[i] ^ (mask & (one[i] ^ zero[i]));
}

void fprime_add(uint8_t *r, const uint8_t *a, const uint8_t *modulus)
{
	raw_add(r, a);
	raw_try_sub(r, modulus);
}

void fprime_sub(uint8_t *r, const uint8_t *a, const uint8_t *modulus)
{
	raw_add(r, modulus);
	raw_try_sub(r, a);
	raw_try_sub(r, modulus);
}

void fprime_mul(uint8_t *r, const uint8_t *a, const uint8_t *b,
		const uint8_t *modulus)
{
	int i;

	memset(r, 0, FPRIME_SIZE);

	for (i = prime_msb(modulus); i >= 0; i--) {
		const uint8_t bit = (b[i >> 3] >> (i & 7)) & 1;
		uint8_t plusa[FPRIME_SIZE];

		shift_n_bits(r, 1);
		raw_try_sub(r, modulus);

		fprime_copy(plusa, r);
		fprime_add(plusa, a, modulus);

		fprime_select(r, r, plusa, bit);
	}
}

void fprime_inv(uint8_t *r, const uint8_t *a, const uint8_t *modulus)
{
	uint8_t pm2[FPRIME_SIZE];
	uint16_t c = 2;
	int i;

	/* Compute (p-2) */
	fprime_copy(pm2, modulus);
	for (i = 0; i < FPRIME_SIZE; i++) {
		c = modulus[i] - c;
		pm2[i] = c;
		c >>= 8;
	}

	/* Binary exponentiation */
	fprime_load(r, 1);

	for (i = prime_msb(modulus); i >= 0; i--) {
		uint8_t r2[FPRIME_SIZE];

		fprime_mul(r2, r, r, modulus);

		if ((pm2[i >> 3] >> (i & 7)) & 1)
			fprime_mul(r, r2, a, modulus);
		else
			fprime_copy(r, r2);
	}
}
/* Montgomery <-> Edwards isomorphism
 * Daniel Beer <dlbeer@gmail.com>, 18 Jan 2014
 *
 * This file is in the public domain.
 */




void morph25519_e2m(uint8_t *montgomery, const uint8_t *y)
{
	uint8_t yplus[F25519_SIZE];
	uint8_t yminus[F25519_SIZE];

	f25519_sub(yplus, f25519_one, y);
	f25519_inv__distinct(yminus, yplus);
	f25519_add(yplus, f25519_one, y);
	f25519_mul__distinct(montgomery, yplus, yminus);
	f25519_normalize(montgomery);
}

void morph25519_mx2ey(uint8_t *ey, const uint8_t *mx)
{
	uint8_t n[F25519_SIZE];
	uint8_t d[F25519_SIZE];

	f25519_add(n, mx, f25519_one);
	f25519_inv__distinct(d, n);
	f25519_sub(n, mx, f25519_one);
	f25519_mul__distinct(ey, n, d);
}

static uint8_t ey2ex(uint8_t *x, const uint8_t *y, int parity)
{
	static const uint8_t d[F25519_SIZE] = {
		0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
		0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
		0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
		0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
	};

	uint8_t a[F25519_SIZE];
	uint8_t b[F25519_SIZE];
	uint8_t c[F25519_SIZE];

	/* Compute c = y^2 */
	f25519_mul__distinct(c, y, y);

	/* Compute b = (1+dy^2)^-1 */
	f25519_mul__distinct(b, c, d);
	f25519_add(a, b, f25519_one);
	f25519_inv__distinct(b, a);

	/* Compute a = y^2-1 */
	f25519_sub(a, c, f25519_one);

	/* Compute c = a*b = (y^2+1)/(1-dy^2) */
	f25519_mul__distinct(c, a, b);

	/* Compute a, b = +/-sqrt(c), if c is square */
	f25519_sqrt(a, c);
	f25519_neg(b, a);

	/* Select one of them, based on the parity bit */
	f25519_select(x, a, b, (a[0] ^ parity) & 1);

	/* Verify that x^2 = c */
	f25519_mul__distinct(a, x, x);
	f25519_normalize(a);
	f25519_normalize(c);

	return f25519_eq(a, c);
}

uint8_t morph25519_m2e(uint8_t *ex, uint8_t *ey,
		       const uint8_t *mx, int parity)
{
	uint8_t ok;

	morph25519_mx2ey(ey, mx);
	ok = ey2ex(ex, ey, parity);

	f25519_normalize(ex);
	f25519_normalize(ey);

	return ok;
}
/* SHA512
 * Daniel Beer <dlbeer@gmail.com>, 22 Apr 2014
 *
 * This file is in the public domain.
 */



const struct sha512_state sha512_initial_state = { {
	0x6a09e667f3bcc908LL, 0xbb67ae8584caa73bLL,
	0x3c6ef372fe94f82bLL, 0xa54ff53a5f1d36f1LL,
	0x510e527fade682d1LL, 0x9b05688c2b3e6c1fLL,
	0x1f83d9abfb41bd6bLL, 0x5be0cd19137e2179LL,
} };

static const uint64_t round_k[80] = {
	0x428a2f98d728ae22LL, 0x7137449123ef65cdLL,
	0xb5c0fbcfec4d3b2fLL, 0xe9b5dba58189dbbcLL,
	0x3956c25bf348b538LL, 0x59f111f1b605d019LL,
	0x923f82a4af194f9bLL, 0xab1c5ed5da6d8118LL,
	0xd807aa98a3030242LL, 0x12835b0145706fbeLL,
	0x243185be4ee4b28cLL, 0x550c7dc3d5ffb4e2LL,
	0x72be5d74f27b896fLL, 0x80deb1fe3b1696b1LL,
	0x9bdc06a725c71235LL, 0xc19bf174cf692694LL,
	0xe49b69c19ef14ad2LL, 0xefbe4786384f25e3LL,
	0x0fc19dc68b8cd5b5LL, 0x240ca1cc77ac9c65LL,
	0x2de92c6f592b0275LL, 0x4a7484aa6ea6e483LL,
	0x5cb0a9dcbd41fbd4LL, 0x76f988da831153b5LL,
	0x983e5152ee66dfabLL, 0xa831c66d2db43210LL,
	0xb00327c898fb213fLL, 0xbf597fc7beef0ee4LL,
	0xc6e00bf33da88fc2LL, 0xd5a79147930aa725LL,
	0x06ca6351e003826fLL, 0x142929670a0e6e70LL,
	0x27b70a8546d22ffcLL, 0x2e1b21385c26c926LL,
	0x4d2c6dfc5ac42aedLL, 0x53380d139d95b3dfLL,
	0x650a73548baf63deLL, 0x766a0abb3c77b2a8LL,
	0x81c2c92e47edaee6LL, 0x92722c851482353bLL,
	0xa2bfe8a14cf10364LL, 0xa81a664bbc423001LL,
	0xc24b8b70d0f89791LL, 0xc76c51a30654be30LL,
	0xd192e819d6ef5218LL, 0xd69906245565a910LL,
	0xf40e35855771202aLL, 0x106aa07032bbd1b8LL,
	0x19a4c116b8d2d0c8LL, 0x1e376c085141ab53LL,
	0x2748774cdf8eeb99LL, 0x34b0bcb5e19b48a8LL,
	0x391c0cb3c5c95a63LL, 0x4ed8aa4ae3418acbLL,
	0x5b9cca4f7763e373LL, 0x682e6ff3d6b2b8a3LL,
	0x748f82ee5defb2fcLL, 0x78a5636f43172f60LL,
	0x84c87814a1f0ab72LL, 0x8cc702081a6439ecLL,
	0x90befffa23631e28LL, 0xa4506cebde82bde9LL,
	0xbef9a3f7b2c67915LL, 0xc67178f2e372532bLL,
	0xca273eceea26619cLL, 0xd186b8c721c0c207LL,
	0xeada7dd6cde0eb1eLL, 0xf57d4f7fee6ed178LL,
	0x06f067aa72176fbaLL, 0x0a637dc5a2c898a6LL,
	0x113f9804bef90daeLL, 0x1b710b35131c471bLL,
	0x28db77f523047d84LL, 0x32caab7b40c72493LL,
	0x3c9ebe0a15c9bebcLL, 0x431d67c49c100d4cLL,
	0x4cc5d4becb3e42b6LL, 0x597f299cfc657e2aLL,
	0x5fcb6fab3ad6faecLL, 0x6c44198c4a475817LL,
};

static inline uint64_t load64(const uint8_t *x)
{
	uint64_t r;

	r = *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);

	return r;
}

static inline void store64(uint8_t *x, uint64_t v)
{
	x += 7;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
}

static inline uint64_t rot64(uint64_t x, int bits)
{
	return (x >> bits) | (x << (64 - bits));
}

void sha512_block(struct sha512_state *s, const uint8_t *blk)
{
	uint64_t w[16];
	uint64_t a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = load64(blk);
		blk += 8;
	}

	/* Load state */
	a = s->h[0];
	b = s->h[1];
	c = s->h[2];
	d = s->h[3];
	e = s->h[4];
	f = s->h[5];
	g = s->h[6];
	h = s->h[7];

	for (i = 0; i < 80; i++) {
		/* Compute value of w[i + 16]. w[wrap(i)] is currently w[i] */
		const uint64_t wi = w[i & 15];
		const uint64_t wi15 = w[(i + 1) & 15];
		const uint64_t wi2 = w[(i + 14) & 15];
		const uint64_t wi7 = w[(i + 9) & 15];
		const uint64_t s0 =
			rot64(wi15, 1) ^ rot64(wi15, 8) ^ (wi15 >> 7);
		const uint64_t s1 =
			rot64(wi2, 19) ^ rot64(wi2, 61) ^ (wi2 >> 6);

		/* Round calculations */
		const uint64_t S0 = rot64(a, 28) ^ rot64(a, 34) ^ rot64(a, 39);
		const uint64_t S1 = rot64(e, 14) ^ rot64(e, 18) ^ rot64(e, 41);
		const uint64_t ch = (e & f) ^ ((~e) & g);
		const uint64_t temp1 = h + S1 + ch + round_k[i] + wi;
		const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
		const uint64_t temp2 = S0 + maj;

		/* Update round state */
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

		/* w[wrap(i)] becomes w[i + 16] */
		w[i & 15] = wi + s0 + wi7 + s1;
	}

	/* Store state */
	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;
}

void sha512_final(struct sha512_state *s, const uint8_t *blk,
		  size_t total_size)
{
	uint8_t temp[SHA512_BLOCK_SIZE] = {0};
	const size_t last_size = total_size & (SHA512_BLOCK_SIZE - 1);

	if (last_size)
		memcpy(temp, blk, last_size);
	temp[last_size] = 0x80;

	if (last_size > 111) {
		sha512_block(s, temp);
		memset(temp, 0, sizeof(temp));
	}

	/* Note: we assume total_size fits in 61 bits */
	store64(temp + SHA512_BLOCK_SIZE - 8, total_size << 3);
	sha512_block(s, temp);
}

void sha512_get(const struct sha512_state *s, uint8_t *hash,
		unsigned int offset, unsigned int len)
{
	int i;

	if (offset > SHA512_BLOCK_SIZE)
		return;

	if (len > SHA512_BLOCK_SIZE - offset)
		len = SHA512_BLOCK_SIZE - offset;

	/* Skip whole words */
	i = offset >> 3;
	offset &= 7;

	/* Skip/read out bytes */
	if (offset) {
		uint8_t tmp[8];
		unsigned int c = 8 - offset;

		if (c > len)
			c = len;

		store64(tmp, s->h[i++]);
		memcpy(hash, tmp + offset, c);
		len -= c;
		hash += c;
	}

	/* Read out whole words */
	while (len >= 8) {
		store64(hash, s->h[i++]);
		hash += 8;
		len -= 8;
	}

	/* Read out bytes */
	if (len) {
		uint8_t tmp[8];

		store64(tmp, s->h[i]);
		memcpy(hash, tmp, len);
	}
}

// Some platforms don't support 128 bit int.
#if defined(__x86_64__)

typedef unsigned __int128 uint128_t;

// from cosmopolitan third_party/mbedtls/everest.c
// Changes made in this file: removed private key preparation in curve25519()
// and pasted the #included files in directly.
// License:
// Cosmopolitan Everest (Apache 2.0)
// Copyright 2024 Justine Alexndra Roberts Tunney
// Copyright 2016-2018 INRIA and Microsoft Corporation
// Changes: Made C code look nice and not have pointers

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __SWAPBE16(x) (x)
#define __SWAPBE32(x) (x)
#define __SWAPBE64(x) (x)
#else
#define __SWAPBE16(x) __builtin_bswap16(x)
#define __SWAPBE32(x) __builtin_bswap32(x)
#define __SWAPBE64(x) __builtin_bswap64(x)
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __SWAPLE16(x) (x)
#define __SWAPLE32(x) (x)
#define __SWAPLE64(x) (x)
#else
#define __SWAPLE16(x) __builtin_bswap16(x)
#define __SWAPLE32(x) __builtin_bswap32(x)
#define __SWAPLE64(x) __builtin_bswap64(x)
#endif

#define READ16LE(P)                    \
  (__extension__({                     \
    uint16_t __x;                      \
    __builtin_memcpy(&__x, P, 16 / 8); \
    __SWAPLE16(__x);                   \
  }))

#define READ16BE(P)                    \
  (__extension__({                     \
    uint16_t __x;                      \
    __builtin_memcpy(&__x, P, 16 / 8); \
    __SWAPBE16(__x);                   \
  }))

#define READ32LE(P)                    \
  (__extension__({                     \
    uint32_t __x;                      \
    __builtin_memcpy(&__x, P, 32 / 8); \
    __SWAPLE32(__x);                   \
  }))

#define READ32BE(P)                    \
  (__extension__({                     \
    uint32_t __x;                      \
    __builtin_memcpy(&__x, P, 32 / 8); \
    __SWAPBE32(__x);                   \
  }))

#define READ64LE(P)                    \
  (__extension__({                     \
    uint64_t __x;                      \
    __builtin_memcpy(&__x, P, 64 / 8); \
    __SWAPLE32(__x);                   \
  }))

#define READ64BE(P)                    \
  (__extension__({                     \
    uint64_t __x;                      \
    __builtin_memcpy(&__x, P, 64 / 8); \
    __SWAPBE64(__x);                   \
  }))

#define WRITE16LE(P, X)                  \
  (__extension__({                       \
    __typeof__(&(P)[0]) __p = (P);       \
    uint16_t __x = __SWAPLE16(X);        \
    __builtin_memcpy(__p, &__x, 16 / 8); \
    __p + 16 / 8;                        \
  }))

#define WRITE16BE(P, X)                  \
  (__extension__({                       \
    __typeof__(&(P)[0]) __p = (P);       \
    uint16_t __x = __SWAPBE16(X);        \
    __builtin_memcpy(__p, &__x, 16 / 8); \
    __p + 16 / 8;                        \
  }))

#define WRITE32LE(P, X)                  \
  (__extension__({                       \
    __typeof__(&(P)[0]) __p = (P);       \
    uint32_t __x = __SWAPLE32(X);        \
    __builtin_memcpy(__p, &__x, 32 / 8); \
    __p + 32 / 8;                        \
  }))

#define WRITE32BE(P, X)                  \
  (__extension__({                       \
    __typeof__(&(P)[0]) __p = (P);       \
    uint32_t __x = __SWAPBE32(X);        \
    __builtin_memcpy(__p, &__x, 32 / 8); \
    __p + 32 / 8;                        \
  }))

#define WRITE64LE(P, X)                  \
  (__extension__({                       \
    __typeof__(&(P)[0]) __p = (P);       \
    uint64_t __x = __SWAPLE64(X);        \
    __builtin_memcpy(__p, &__x, 64 / 8); \
    __p + 64 / 8;                        \
  }))

#define WRITE64BE(P, X)                  \
  (__extension__({                       \
    __typeof__(&(P)[0]) __p = (P);       \
    uint64_t __x = __SWAPBE64(X);        \
    __builtin_memcpy(__p, &__x, 64 / 8); \
    __p + 64 / 8;                        \
  }))

#define Read32be(S)                                      \
  ({                                                     \
    const uint8_t *Ptr = (S);                            \
    ((uint32_t)Ptr[0] << 030 | (uint32_t)Ptr[1] << 020 | \
     (uint32_t)Ptr[2] << 010 | (uint32_t)Ptr[3] << 000); \
  })

#define Write32be(P, V)                         \
  ({                                            \
    uint8_t *OuT = (P);                         \
    uint64_t VaL = (V);                         \
    OuT[0] = (0x00000000FF000000 & VaL) >> 030; \
    OuT[1] = (0x0000000000FF0000 & VaL) >> 020; \
    OuT[2] = (0x000000000000FF00 & VaL) >> 010; \
    OuT[3] = (0x00000000000000FF & VaL) >> 000; \
    OuT + 4;                                    \
  })

#define Read64be(S)                                      \
  ({                                                     \
    const uint8_t *Ptr = (S);                            \
    ((uint64_t)Ptr[0] << 070 | (uint64_t)Ptr[1] << 060 | \
     (uint64_t)Ptr[2] << 050 | (uint64_t)Ptr[3] << 040 | \
     (uint64_t)Ptr[4] << 030 | (uint64_t)Ptr[5] << 020 | \
     (uint64_t)Ptr[6] << 010 | (uint64_t)Ptr[7] << 000); \
  })

#define Write64be(P, V)                         \
  ({                                            \
    uint64_t VaL = (V);                         \
    uint8_t *OuT = (P);                         \
    OuT[0] = (0xFF00000000000000 & VaL) >> 070; \
    OuT[1] = (0x00FF000000000000 & VaL) >> 060; \
    OuT[2] = (0x0000FF0000000000 & VaL) >> 050; \
    OuT[3] = (0x000000FF00000000 & VaL) >> 040; \
    OuT[4] = (0x00000000FF000000 & VaL) >> 030; \
    OuT[5] = (0x0000000000FF0000 & VaL) >> 020; \
    OuT[6] = (0x000000000000FF00 & VaL) >> 010; \
    OuT[7] = (0x00000000000000FF & VaL) >> 000; \
    OuT + 8;                                    \
  })

#define Write64le(P, V)                         \
  ({                                            \
    uint64_t VaL = (V);                         \
    uint8_t *OuT = (P);                         \
    OuT[0] = (0x00000000000000FF & VaL) >> 000; \
    OuT[1] = (0x000000000000FF00 & VaL) >> 010; \
    OuT[2] = (0x0000000000FF0000 & VaL) >> 020; \
    OuT[3] = (0x00000000FF000000 & VaL) >> 030; \
    OuT[4] = (0x000000FF00000000 & VaL) >> 040; \
    OuT[5] = (0x0000FF0000000000 & VaL) >> 050; \
    OuT[6] = (0x00FF000000000000 & VaL) >> 060; \
    OuT[7] = (0xFF00000000000000 & VaL) >> 070; \
    OuT + 8;                                    \
  })

#define GET_UINT32_BE(n, b, i) (n) = Read32be((b) + (i))
#define PUT_UINT32_BE(n, b, i) Write32be((b) + (i), n)
#define GET_UINT64_BE(n, b, i) (n) = Read64be((b) + (i))
#define PUT_UINT64_BE(n, b, i) Write64be((b) + (i), n)

#define DW(x)     (uint128_t)(x)
#define EQ(x, y)  ((((x ^ y) | (~(x ^ y) + 1)) >> 63) - 1)
#define GTE(x, y) (((x ^ ((x ^ y) | ((x - y) ^ y))) >> 63) - 1)

void HaclBignumCopy(uint64_t o[5], uint64_t p[5]) {
  for (unsigned i = 0; i < 5; ++i) {
    o[i] = p[i];
  }
}

void HaclBignumFsum(uint64_t o[5], uint64_t p[5]) {
  for (unsigned i = 0; i < 5; ++i) {
    o[i] += p[i];
  }
}

void HaclBignumTrunc(uint64_t o[5], uint128_t p[5]) {
  for (unsigned i = 0; i < 5; ++i) {
    o[i] = p[i];
  }
}

void HaclBignumCarry(uint64_t p[5]) {
  for (unsigned i = 0; i < 4; ++i) {
    p[i + 1] += p[i] >> 51;
    p[i] &= 0x7ffffffffffff;
  }
}

void HaclBignumCarryWide(uint128_t p[5]) {
  for (unsigned i = 0; i < 4; ++i) {
    p[i + 1] += p[i] >> 51;
    p[i] &= 0x7ffffffffffff;
  }
}

static void HaclBignumFmulReduce(uint128_t o[5], uint64_t p[5], uint64_t q[5]) {
  uint64_t t;
  unsigned i, j;
  for (i = 0;; ++i) {
    for (j = 0; j < 5; ++j) {
      o[j] += DW(p[j]) * q[i];
    }
    if (i == 4) break;
    t = p[4] * 19;
    p[4] = p[3];
    p[3] = p[2];
    p[2] = p[1];
    p[1] = p[0];
    p[0] = t;
  }
}

static void HaclBignumFmul(uint64_t o[5], uint64_t p[5], uint64_t q[5]) {
  uint128_t t[5] = {0};
  uint64_t u[5] = {p[0], p[1], p[2], p[3], p[4]};
  HaclBignumFmulReduce(t, u, q);
  HaclBignumCarryWide(t);
  t[0] += DW(19) * (uint64_t)(t[4] >> 51);
  HaclBignumTrunc(o, t);
  o[1] += o[0] >> 51;
  o[4] &= 0x7ffffffffffff;
  o[0] &= 0x7ffffffffffff;
}

static void HaclBignumFsquare(uint128_t t[5], uint64_t p[5]) {
  t[0] = DW(p[0] * 1) * p[0] + DW(p[4] * 38) * p[1] + DW(p[2] * 38) * p[3];
  t[1] = DW(p[0] * 2) * p[1] + DW(p[4] * 38) * p[2] + DW(p[3] * 19) * p[3];
  t[2] = DW(p[0] * 2) * p[2] + DW(p[1] * 01) * p[1] + DW(p[4] * 38) * p[3];
  t[3] = DW(p[0] * 2) * p[3] + DW(p[1] * 02) * p[2] + DW(p[4]) * (p[4] * 19);
  t[4] = DW(p[0] * 2) * p[4] + DW(p[1] * 02) * p[3] + DW(p[2]) * p[2];
}

static void HaclBignumFsqa(uint64_t o[5], uint32_t n) {
  uint128_t t[5];
  for (unsigned i = 0; i < n; ++i) {
    HaclBignumFsquare(t, o);
    HaclBignumCarryWide(t);
    t[0] += DW(19) * (uint64_t)(t[4] >> 51);
    HaclBignumTrunc(o, t);
    o[1] += o[0] >> 51;
    o[4] &= 0x7ffffffffffff;
    o[0] &= 0x7ffffffffffff;
  }
}

static void HaclBignumFsqr(uint64_t o[5], uint64_t p[5], uint32_t n) {
  HaclBignumCopy(o, p);
  HaclBignumFsqa(o, n);
}

static void HaclBignumCrecip(uint64_t o[5], uint64_t z[5]) {
  uint64_t b[4][5];
  HaclBignumFsqr(b[0], z, 1);
  HaclBignumFsqr(b[1], b[0], 2);
  HaclBignumFmul(b[2], b[1], z);
  HaclBignumFmul(b[0], b[2], b[0]);
  HaclBignumFsqr(b[1], b[0], 1);
  HaclBignumFmul(b[2], b[1], b[2]);
  HaclBignumFsqr(b[1], b[2], 5);
  HaclBignumFmul(b[2], b[1], b[2]);
  HaclBignumFsqr(b[1], b[2], 10);
  HaclBignumFmul(b[3], b[1], b[2]);
  HaclBignumFsqr(b[1], b[3], 20);
  HaclBignumFmul(b[1], b[1], b[3]);
  HaclBignumFsqa(b[1], 10);
  HaclBignumFmul(b[2], b[1], b[2]);
  HaclBignumFsqr(b[1], b[2], 50);
  HaclBignumFmul(b[3], b[1], b[2]);
  HaclBignumFsqr(b[1], b[3], 100);
  HaclBignumFmul(b[1], b[1], b[3]);
  HaclBignumFsqa(b[1], 50);
  HaclBignumFmul(b[1], b[1], b[2]);
  HaclBignumFsqa(b[1], 5);
  HaclBignumFmul(o, b[1], b[0]);
}

static void HaclBignumFdif(uint64_t a[5], uint64_t b[5]) {
  a[0] = b[0] + 0x3fffffffffff68 - a[0];
  a[1] = b[1] + 0x3ffffffffffff8 - a[1];
  a[2] = b[2] + 0x3ffffffffffff8 - a[2];
  a[3] = b[3] + 0x3ffffffffffff8 - a[3];
  a[4] = b[4] + 0x3ffffffffffff8 - a[4];
}

static void HaclBignumFscalar(uint64_t o[5], uint64_t p[5], uint64_t s) {
  unsigned i;
  uint128_t t[5];
  for (i = 0; i < 5; ++i) t[i] = DW(p[i]) * s;
  HaclBignumCarryWide(t);
  t[0] += DW(19) * (uint64_t)(t[4] >> 51);
  t[4] &= 0x7ffffffffffff;
  HaclBignumTrunc(o, t);
}

static void HaclEcPointSwap(uint64_t a[2][5], uint64_t b[2][5], uint64_t m) {
  unsigned i, j;
  uint64_t x, y;
  for (i = 0; i < 2; ++i) {
    for (j = 0; j < 5; ++j) {
      x = a[i][j] ^ (-m & (a[i][j] ^ b[i][j]));
      y = b[i][j] ^ (-m & (a[i][j] ^ b[i][j]));
      a[i][j] = x;
      b[i][j] = y;
    }
  }
}

static void HaclEcFormatFexpand(uint64_t o[5], const uint8_t p[32]) {
  o[0] = READ64LE(p + 000) >> 00 & 0x7ffffffffffff;
  o[1] = READ64LE(p + 006) >> 03 & 0x7ffffffffffff;
  o[2] = READ64LE(p + 014) >> 06 & 0x7ffffffffffff;
  o[3] = READ64LE(p + 023) >> 01 & 0x7ffffffffffff;
  o[4] = READ64LE(p + 030) >> 12 & 0x7ffffffffffff;
}

static void HaclEcFormatFcontract(uint8_t o[32], uint64_t p[5]) {
  uint64_t m;
  HaclBignumCarry(p);
  p[0] += 19 * (p[4] >> 51);
  p[4] &= 0x7ffffffffffff;
  HaclBignumCarry(p);
  p[0] += 19 * (p[4] >> 51);
  p[1] += p[0] >> 51;
  p[0] &= 0x7ffffffffffff;
  p[1] &= 0x7ffffffffffff;
  p[4] &= 0x7ffffffffffff;
  m = GTE(p[0], 0x7ffffffffffed);
  m &= EQ(p[1], 0x7ffffffffffff);
  m &= EQ(p[2], 0x7ffffffffffff);
  m &= EQ(p[3], 0x7ffffffffffff);
  m &= EQ(p[4], 0x7ffffffffffff);
  p[0] -= 0x7ffffffffffed & m;
  p[1] -= 0x7ffffffffffff & m;
  p[2] -= 0x7ffffffffffff & m;
  p[3] -= 0x7ffffffffffff & m;
  p[4] -= 0x7ffffffffffff & m;
  Write64le(o + 000, p[1] << 51 | p[0] >> 00);
  Write64le(o + 010, p[2] << 38 | p[1] >> 13);
  Write64le(o + 020, p[3] << 25 | p[2] >> 26);
  Write64le(o + 030, p[4] << 12 | p[3] >> 39);
}

static void HaclEcFormatScalarOfPoint(uint8_t o[32], uint64_t p[2][5]) {
  uint64_t t[2][5];
  HaclBignumCrecip(t[0], p[1]);
  HaclBignumFmul(t[1], p[0], t[0]);
  HaclEcFormatFcontract(o, t[1]);
}

static void HaclEcAddAndDoubleFmonty(uint64_t xz2[2][5], uint64_t xz3[2][5],
                                     uint64_t xz[2][5], uint64_t xzprime[2][5],
                                     uint64_t qx[5]) {
  uint64_t b[7][5];
  HaclBignumCopy(b[0], xz[0]);
  HaclBignumFsum(xz[0], xz[1]);
  HaclBignumFdif(xz[1], b[0]);
  HaclBignumCopy(b[0], xzprime[0]);
  HaclBignumFsum(xzprime[0], xzprime[1]);
  HaclBignumFdif(xzprime[1], b[0]);
  HaclBignumFmul(b[4], xzprime[0], xz[1]);
  HaclBignumFmul(b[5], xz[0], xzprime[1]);
  HaclBignumCopy(b[0], b[4]);
  HaclBignumFsum(b[4], b[5]);
  HaclBignumFdif(b[5], b[0]);
  HaclBignumFsqr(xz3[0], b[4], 1);
  HaclBignumFsqr(b[6], b[5], 1);
  HaclBignumFmul(xz3[1], b[6], qx);
  HaclBignumFsqr(b[2], xz[0], 1);
  HaclBignumFsqr(b[3], xz[1], 1);
  HaclBignumFmul(xz2[0], b[2], b[3]);
  HaclBignumFdif(b[3], b[2]);
  HaclBignumFscalar(b[1], b[3], 121665);
  HaclBignumFsum(b[1], b[2]);
  HaclBignumFmul(xz2[1], b[1], b[3]);
}

/**
 * Computes elliptic curve 25519.
 */
void curve25519(uint8_t mypublic[32], const uint8_t secret[32],
                const uint8_t basepoint[32]) {
  uint32_t i, j;
  uint8_t e[32], s;
  uint64_t q[5], t[4][2][5] = {{{1}}, {{0}, {1}}};
  HaclEcFormatFexpand(q, basepoint);
  for (j = 0; j < 32; ++j) e[j] = secret[j];
  //e[0] &= 248;
  //e[31] = (e[31] & 127) | 64;
  HaclBignumCopy(t[1][0], q);
  for (i = 32; i--;) {
    for (s = e[i], j = 4; j--;) {
      HaclEcPointSwap(t[0], t[1], s >> 7);
      HaclEcAddAndDoubleFmonty(t[2], t[3], t[0], t[1], q);
      HaclEcPointSwap(t[2], t[3], s >> 7);
      s <<= 1;
      HaclEcPointSwap(t[2], t[3], s >> 7);
      HaclEcAddAndDoubleFmonty(t[0], t[1], t[2], t[3], q);
      HaclEcPointSwap(t[0], t[1], s >> 7);
      s <<= 1;
    }
  }
  HaclEcFormatScalarOfPoint(mypublic, t[0]);
}

#endif
