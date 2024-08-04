#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>

#include <sys/random.h>

#include "curve25519.h"

static const uint8_t basepoint[32] = {9};

typedef uint8_t Key[32];
typedef Key PrivateKey;
typedef Key PublicKey;
typedef Key EdKey;
// struct IdentityKey {PublicKey pub; EdKey ed; };
typedef uint8_t SerializedKey[1+32];
typedef uint8_t OmemoSerializedKey[32];
typedef uint8_t CurveSignature[64];

struct KeyPair {
  PrivateKey prv;
  PublicKey pub;
};

struct PreKey {
  uint32_t id;
  struct KeyPair kp;
};

struct PreKeyStore {
  struct PreKey[100] keys;
};

struct SignedPreKey {
  struct KeyPair kp;
  CurveSignature sig, omemosig;
};

struct Session {
  struct KeyPair identity;
};

// Random function that must not fail, if it's really not possible to
// get random data, you should either exit the program or longjmp out.
void SystemRandom(void *d, size_t n);
// void SystemRandom(void *d, size_t n) { esp_fill_random(d, n); }

void SystemRandom(void *d, size_t n) {
  assert(getrandom(d, n, 0) == n);
}

// Note: spk will be the serialized version in the XML bundle: 0x05 prepended making 33 bytes.
struct Bundle {
  CurveSignature spks;
  PublicKey spk, ik;
  PublicKey prekeys[150];
  size_t prekeysn;
};

static void GenerateKeyPair(struct KeyPair *kp) {
  memset(kp, 0, sizeof(*kp));
  SystemRandom(kp->prv, sizeof(kp->prv));
  kp->prv[0] &= 248;
  kp->prv[31] &= 127;
  kp->prv[31] |= 64;
  // It always returns 0, no err checking needed.
  curve25519_donna(kp->pub, kp->prv, basepoint);
}

static void GeneratePreKeys(struct PreKeyStore *store) {
  for (int i = 0; i < 100; i++) {
    GenerateKeyPair(&store->keys[i].kp);
    store->keys[i].id = i;
  }
}

static void GenerateIdentityKeyPair(struct KeyPair *kp) {
  GenerateKeyPair(kp);
}

static void GenerateRegistrationId(uint32_t *id) {
  SystemRandom(id, sizeof(*id));
  *id = (*id % 16380) + 1;
}

static void SerializeKey(SerializedKey k, Key pub) {
  k[0] = 5;
  memcpy(k+1, pub, sizeof(SerializedKey)-1);
}

static void SerializeKeyOmemo(OmemoSerializedKey sk, Key pub) {
  memcpy(sk, pub, sizeof(OmemoSerializedKey));
}

static int CalculateCurveSignature(CurveSignature cs, Key signprv, const uint8_t *msg, size_t n) {
  uint8_t rnd[sizeof(CurveSignature)];
  SystemRandom(rnd, sizeof(rnd));
  // TODO: change this function so it doesn't fail
  if (xed25519_sign(cs, signprv, msg, n, rnd) < 0)
    return -1;
  return 0;
}

static void DecodeEdPoint(PublicKey pub, EdKey ed) {
  fe y, u;
  crypto_sign_ed25519_ref10_fe_frombytes(y, ed);
  fe_edy_to_montx(u, y);
  crypto_sign_ed25519_ref10_fe_tobytes(pub, u);
}

static void DecodePointMont(PublicKey pub, PublicKey data) {
  memcpy(pub, data, sizeof(PublicKey));
}

static void DecodePrivatePoint(PrivateKey prv, PrivateKey data) {
  memcpy(prv, data, sizeof(PrivateKey));
}

static void GenerateSignedPreKey(struct SignedPreKey *spk, struct KeyPair *idkp) {
  struct KeyPair kp;
  SerializedKey sk;
  OmemoSerializedKey omemok;
  GenerateKeyPair(&kp);
  SerializeKey(sk, kp.pub);
  SerializeKeyOmemo(omemok, kp.pub);
  CalculateCurveSignature(spk->sig, idkp->prv, sk, sizeof(SerializedKey));
  CalculateCurveSignature(spk->omemosig, idkp->prv, omemok, sizeof(SerializedKeyOmemo));
}

static bool VerifySignature(CurveSignature sig, PublicKey sk, const uint8_t *msg, size_t n) {
  return curve25519_verify(sig, sk, msg, n) == 0;
}

// What this function would do in libomemo-c is get the identity keypair
// from a callback and memcpy everything.
static void GetIdentityKeyPair(struct KeyPair *ouridkeypair) {
  PublicKey pub;
  PrivateKey prv;
  // TODO: check if it's always plain pub key and not ed or Serialized
  DecodePointMont(pub, ouridkeypair->pub);
  DecodePrivatePoint(prv, ouridkeypair->prv);
}

static void ProcessBundle(struct Bundle *b) {
  SerializedKey serspk;
  struct KeyPair ourbasekey;
  // if (version == 4) SerializedKeyOmemo()
  SerializeKey(serspk, b->spk);
  if (!VerifySignature(b->spks, b->ik, serspk, sizeof(SerializedKey))) {
    puts("Wrong sig on device");
  }
  GenerateKeyPair(&outbasekey);
}
