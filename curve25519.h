#ifndef CURVE25519_H
#define CURVE25519_H

typedef int crypto_int32;
typedef crypto_int32 fe[10];

void crypto_sign_ed25519_ref10_fe_frombytes(fe,const unsigned char *);
void fe_edy_to_montx(fe u, const fe y);
void crypto_sign_ed25519_ref10_fe_tobytes(unsigned char *,const fe);
void fe_montx_to_edy(fe y, const fe u);
int curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint);
int ed25519_verify(const unsigned char* signature,
                      const unsigned char* curve25519_pubkey,
                      const unsigned char* msg, const unsigned long msg_len);
int curve25519_verify(const unsigned char* signature,
                      const unsigned char* curve25519_pubkey,
                      const unsigned char* msg, const unsigned long msg_len);
int xed25519_sign(unsigned char* signature_out,
                  const unsigned char* curve25519_privkey,
                  const unsigned char* msg, const unsigned long msg_len,
                  const unsigned char* random);
int generalized_xveddsa_25519_verify(
                  unsigned char* vrf_out,
                  const unsigned char* signature,
                  const unsigned char* x25519_pubkey_bytes,
                  const unsigned char* msg,
                  const unsigned long msg_len,
                  const unsigned char* customization_label,
                  const unsigned long customization_label_len);
int generalized_xveddsa_25519_sign(
                  unsigned char* signature_out,
                  const unsigned char* x25519_privkey_scalar,
                  const unsigned char* msg,
                  const unsigned long msg_len,
                  const unsigned char* random,
                  const unsigned char* customization_label,
                  const unsigned long customization_label_len);

#endif
