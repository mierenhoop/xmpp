#include <mbedtls/hkdf.h>

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
  struct PreKey keys[100];
};

struct SignedPreKey {
  struct KeyPair kp;
  CurveSignature sig, omemosig;
};

struct Session {
  struct KeyPair identity;
};

struct Ratchet {
  Key root;
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
  PublicKey pk; // Randomly selected prekey
  //PublicKey prekeys[150];
  //size_t prekeysn;
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

// AKA ECDHE
static void CalculateCurveAgreement(uint8_t d[static 32], PublicKey pub, PrivateKey prv) {
  curve25519_donna(d, prv, pub);
}

static void GenerateSignedPreKey(struct SignedPreKey *spk, struct KeyPair *idkp) {
  struct KeyPair kp;
  SerializedKey sk;
  OmemoSerializedKey omemok;
  GenerateKeyPair(&kp);
  SerializeKey(sk, kp.pub);
  SerializeKeyOmemo(omemok, kp.pub);
  CalculateCurveSignature(spk->sig, idkp->prv, sk, sizeof(SerializedKey));
  CalculateCurveSignature(spk->omemosig, idkp->prv, omemok, sizeof(OmemoSerializedKey));
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

static void CalculateSendingRatchet(struct Session *session, PublicKey spk, struct KeyPair *sendingkey, Key rootkey) {
  uint8_t secret[32];
  CalculateCurveAgreement(secret, spk, sendingkey->prv);
}

static void InitSessionAlice(struct Bundle *bundle, struct Session *session, struct KeyPair *base) {
  uint8_t secret[32*5];
  memset(secret, 255, 32);
  CalculateCurveAgreement(secret+32, bundle->spk, session->identity.prv);
  CalculateCurveAgreement(secret+64, bundle->ik, base->prv);
  CalculateCurveAgreement(secret+96, bundle->spk, base->prv);
  CalculateCurveAgreement(secret+128, bundle->pk, base->prv);

  uint8_t masterkey[64];
  uint8_t salt[32];
  memset(salt, 0, 32);
  // "OMEMO X3DH" for 0.4.0+
  assert(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, 32, secret, sizeof(secret), "WhisperText", 11, masterkey, 64) == 0);

  struct KeyPair sendingkey;
  GenerateKeyPair(&sendingkey);
  CalculateSendingRatchet(session, bundle->spk, &sendingkey, masterkey);
}

// When we process the bundle, we are the ones who initialize the
// session and we are referred to as alice. Otherwise we have received
// an initiation message and are called bob.
static void ProcessBundle(struct Session *s, struct Bundle *b) {
  SerializedKey serspk;
  struct KeyPair ourbasekey;
  // if (version == 4) SerializedKeyOmemo()
  SerializeKey(serspk, b->spk);
  if (!VerifySignature(b->spks, b->ik, serspk, sizeof(SerializedKey))) {
    puts("Wrong sig on device");
  }
  GenerateKeyPair(&ourbasekey);
  InitSessionAlice(b, s, &ourbasekey);
}

static const uint8_t *ParseVarInt(const uint8_t *s, const uint8_t *e, uint32_t *v) {
  int i = 0;
  *v = 0;
  do {
    if (s >= e)
      return NULL;
    *v |= (*s & 0x7f) << i;
    i += 7;
    if (i > 32 - 7) // will overflow
      return NULL;
  } while (*s++ & 0x80);
  return s;
}

// Only supports uint32 and len prefixed (by int32).
struct MessageSchemaEntry {
  int type;
  uint32_t v;
  const uint8_t *p;
};

#define PB_REQUIRED (1 << 3)
#define PB_UINT32 0
#define PB_LEN 2

// nfields MUST be <= 32
static int ParseProtobuf(const char *s, size_t n, struct MessageSchemaEntry *fields, int nfields) {
  int type, id;
  uint64_t v;
  const char *e = s + n;
  uint32_t found;
  while (s < e) {
    type = *s & 7;
    id = *s >> 3;
    s++;
    if (id >= nfields || type != fields[id].type & 7)
      return -1;
    found |= 1 << id;
    if (!(s = ParseVarInt(s, e, &fields[id].v)))
      return -1;
    if (type == PB_LEN) {
      fields[id].p = s;
      s += fields[id].v;
    }
  }
  for (int i = 0; i < nfields; i++) {
    if (fields[i].type & PB_REQUIRED && !(found & (1 << i)))
      return -1;
  }
  return 0;
}

static void ParseKeyExchange() {
  struct MessageSchemaEntry fields[6] = {
    [1] = {PB_REQUIRED | PB_UINT32},
    [2] = {PB_REQUIRED | PB_UINT32},
    [3] = {PB_REQUIRED | PB_LEN},
    [4] = {PB_REQUIRED | PB_LEN},
    [5] = {PB_REQUIRED | PB_LEN},
  };
}

static uint8_t *FormatVarInt(uint8_t d[static 5], uint32_t v) {
  do {
    *d = v & 0x7f;
    v >>= 7;
    *d++ |= (!!v << 7);
  } while (v);
  return d;
}

static void TestProtobuf() {
  uint8_t varint[5];
  assert(FormatVarInt(varint, 0) == varint + 1 && varint[0] == 0);
  assert(FormatVarInt(varint, 1) == varint + 1 && varint[0] == 1);
  assert(FormatVarInt(varint, 0x80) == varint + 2 && !memcmp(varint, "\x80\x01", 2));
}

int main() {
  TestProtobuf();
  puts("Tests succeeded");
}
