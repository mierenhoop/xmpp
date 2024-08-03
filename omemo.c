#include <stdint.h>
#include <string.h>

#include <sys/random.h>

#include "curve25519.h"

static const uint8_t basepoint[32] = {9};

typedef uint8_t Key[32];
typedef uint8_t SerializedKey[1+32];
typedef uint8_t CurveSignature[64];

struct KeyPair {
  Key prv, pub;
};

static int GenerateKeyPair(struct KeyPair *kp) {
  memset(kp, 0, sizeof(*kp));
  // TODO: make a random function that never fails??
  if (getrandom(kp->prv, sizeof(kp->prv), 0) != sizeof(kp->prv))
    return -1;
  kp->prv[0] &= 248;
  kp->prv[31] &= 127;
  kp->prv[31] |= 64;
  if (curve25519_donna(kp->pub, kp->prv, basepoint) < 0)
    return -1;
  return 0;
}

static void GeneratePreKeys() {
  struct KeyPair kp;
  for (int i = 0; i < 100; i++) {
    GenerateKeyPair(&kp);
  }
}

static int GenerateIdentityKeyPair(struct KeyPair *kp) {
  return GenerateKeyPair(kp);
}

static int GenerateRegistrationId(uint32_t *id) {
  if (getrandom(id, sizeof(*id), 0) != sizeof(*id))
    return -1;
  *id = (*id % 16380) + 1;
  return 0;
}

static void SerializeKey(SerializedKey k, Key pub) {
  k[0] = 5;
  memcpy(k+1, pub, sizeof(SerializedKey)-1);
}

static void SerializeKeyOmemo(Key sk, Key pub) {
  memcpy(sk, pub, sizeof(Key));
}

static int CalculateCurveSignature(CurveSignature cs, Key signprv, const char *msg, size_t n) {
  uint8_t rnd[sizeof(CurveSignature)];
  if (getrandom(rnd, sizeof(rnd), 0) != sizeof(rnd))
    return -1;
  // TODO: change this function so it doesn't fail
  if (xed25519_sign(cs, signprv, msg, n, rnd) < 0)
    return -1;
  return 0;
}

static void GenerateSignedPreKey(struct KeyPair *idkp) {
  struct KeyPair kp;
  SerializedKey sk;
  Key omemok;
  CurveSignature sig, omemosig;
  GenerateKeyPair(&kp);
  SerializeKey(sk, kp.pub);
  SerializeKeyOmemo(omemok, kp.pub);
  CalculateCurveSignature(sig, idkp->prv, sk, sizeof(sk));
  CalculateCurveSignature(omemosig, idkp->prv, omemok, sizeof(omemok));
}
