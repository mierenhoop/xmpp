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
// TODO: are all PublicKey's actually serialized keys here?
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
  uint32_t id;
  struct KeyPair kp;
  CurveSignature sig, omemosig;
};

// TODO: pack for serialization?
struct Session {
  struct KeyPair identity;
};

struct Ratchet {
  Key root;
  Key chain;
};

// Random function that must not fail, if it's really not possible to
// get random data, you should either exit the program or longjmp out.
void SystemRandom(void *d, size_t n);
// void SystemRandom(void *d, size_t n) { esp_fill_random(d, n); }

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

static void GeneratePreKey(struct PreKey *pk, uint32_t id) {
    pk->id = id;
    GenerateKeyPair(&pk->kp);
}

static void GeneratePreKeys(struct PreKeyStore *store) {
  for (int i = 0; i < 100; i++) {
    GeneratePreKey(&store->keys[i], i);
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
  // TODO: OMEMO uses xed25519 and old libsignal uses curve25519
  uint8_t rnd[sizeof(CurveSignature)];
  SystemRandom(rnd, sizeof(rnd));
  // TODO: change this function so it doesn't fail
  assert(xed25519_sign(cs, signprv, msg, n, rnd) >= 0);
  //assert(curve25519_sign(cs, signprv, msg, n, rnd) >= 0);
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

static void GenerateSignedPreKey(struct SignedPreKey *spk, uint32_t id, struct KeyPair *idkp) {
  SerializedKey sk;
  OmemoSerializedKey omemok;
  spk->id = id;
  GenerateKeyPair(&spk->kp);
  SerializeKey(sk, spk->kp.pub);
  SerializeKeyOmemo(omemok, spk->kp.pub);
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

// CKs, mk = KDF_CK(CKs)
// header = HEADER(DHs, PN, Ns)
// Ns += 1
// return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
static void EncryptRatchet(struct Ratchet *ratchet) {
  uint8_t salt[32], output[80];
  memset(salt, 0, 32);
  assert(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, 32, ratchet->chain, sizeof(Key), "WhisperMessageKeys", 18, output, 80) == 0);
  memcpy(ratchet->chain, output, 32);
}

// RK, CKs = KDF_RK(SK, DH(DHs, DHr))
static void CalculateSendingRatchet(struct Session *session, PublicKey spk, struct KeyPair *sendingkey, struct Ratchet *ratchet) {
  uint8_t secret[32], masterkey[64];
  CalculateCurveAgreement(secret, spk, sendingkey->prv);
  assert(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), ratchet->root, sizeof(Key), secret, sizeof(secret), "WhisperRatchet", 14, masterkey, 64) == 0);
  memcpy(ratchet->root, masterkey, sizeof(Key));
  memcpy(ratchet->chain, masterkey+32, 32);
}

// DH1 = DH(IKA, SPKB)
// DH2 = DH(EKA, IKB)
// DH3 = DH(EKA, SPKB)
// DH4 = DH(EKA, OPKB)
// SK = KDF(DH1 || DH2 || DH3 || DH4)
//
// DHs = GENERATE_DH()
static void InitSessionAlice(struct Bundle *bundle, struct Session *session, struct KeyPair *base) {
  uint8_t secret[32*5];
  memset(secret, 255, 32);
  CalculateCurveAgreement(secret+32, bundle->spk, session->identity.prv);
  CalculateCurveAgreement(secret+64, bundle->ik, base->prv);
  CalculateCurveAgreement(secret+96, bundle->spk, base->prv);
  // OMEMO mandates that the bundle MUST contain a prekey.
  CalculateCurveAgreement(secret+128, bundle->pk, base->prv);

  uint8_t masterkey[64];
  uint8_t salt[32];
  memset(salt, 0, 32);
  // "OMEMO X3DH" for 0.4.0+
  assert(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, 32, secret, sizeof(secret), "WhisperText", 11, masterkey, 64) == 0);

  struct Ratchet ratchet;
  memcpy(ratchet.root, masterkey, sizeof(Key));
  struct KeyPair sendingkey;
  GenerateKeyPair(&sendingkey);
  CalculateSendingRatchet(session, bundle->spk, &sendingkey, &ratchet);
}

// When we process the bundle, we are the ones who initialize the
// session and we are referred to as alice. Otherwise we have received
// an initiation message and are called bob.
static int ProcessBundle(struct Session *s, struct Bundle *b) {
  SerializedKey serspk;
  struct KeyPair ourbasekey;
  // if (version == 4) SerializedKeyOmemo()
  SerializeKey(serspk, b->spk);
  if (!VerifySignature(b->spks, b->ik, serspk, sizeof(SerializedKey))) {
     return -1;
  }
  GenerateKeyPair(&ourbasekey);
  InitSessionAlice(b, s, &ourbasekey);
  return 0;
}

// Protobuf: https://protobuf.dev/programming-guides/encoding/

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
struct ProtobufField {
  int type;
  uint32_t v;
  const uint8_t *p;
};

#define PB_REQUIRED (1 << 3)
#define PB_UINT32 0
#define PB_LEN 2

// nfields MUST be <= 16
static int ParseProtobuf(const char *s, size_t n, struct ProtobufField *fields, int nfields) {
  int type, id;
  uint64_t v;
  const char *e = s + n;
  uint32_t found = 0;
  while (s < e) {
    // This is actually a varint, but we only support id < 16 and return an
    // error otherwise, so we don't have to account for multiple-byte tags.
    type = *s & 7;
    id = *s >> 3;
    s++;
    if (id >= nfields || type != (fields[id].type & 7))
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
    if ((fields[i].type & PB_REQUIRED) && !(found & (1 << i)))
      return -1;
  }
  return 0;
}

static int ParseKeyExchange(const uint8_t *s, size_t n) {
  int r;
  struct ProtobufField fields[6] = {
    [1] = {PB_REQUIRED | PB_UINT32},
    [2] = {PB_REQUIRED | PB_UINT32},
    [3] = {PB_REQUIRED | PB_LEN},
    [4] = {PB_REQUIRED | PB_LEN},
    [5] = {PB_REQUIRED | PB_LEN},
  };
  if ((r = ParseProtobuf(s, n, fields, 6)))
    return r;
  return 0;
}

static uint8_t *FormatVarInt(uint8_t d[static 5], uint32_t v) {
  do {
    *d = v & 0x7f;
    v >>= 7;
    *d++ |= (!!v << 7);
  } while (v);
  return d;
}

// id < 16 && n < 128
static uint8_t *FormatBytes(uint8_t *d, int id, uint8_t *b, int n) {
  *d++ = (id << 3) | PB_LEN;
  *d++ = n;
  memcpy(d, b, n);
  return d + n;
}

static void FormatKeyExchange(uint8_t *d, uint32_t pk_id, uint32_t spk_id, PublicKey ik, PublicKey ek) { // , message
  *d++ = (1 << 3) | PB_UINT32;
  d = FormatVarInt(d, pk_id);
  *d++ = (2 << 3) | PB_UINT32;
  d = FormatVarInt(d, spk_id);
  d = FormatBytes(d, 3, ik, sizeof(PublicKey));
  d = FormatBytes(d, 4, ek, sizeof(PublicKey));
}

// OMEMOMessage.proto without ciphertext
static uint8_t *FormatMessageHeader(uint8_t d[46], uint32_t n, uint32_t pn, PublicKey dh_pub) {
  *d++ = (1 << 3) | PB_UINT32;
  d = FormatVarInt(d, n);
  *d++ = (2 << 3) | PB_UINT32;
  d = FormatVarInt(d, pn);
  return FormatBytes(d, 3, dh_pub, sizeof(PublicKey));
}

// Tests

// In the tests we spoof the random source as a hacky way to generate
// the exact private key we want.
static bool testrand;
static uint8_t testrandsrc[100];

void SystemRandom(void *d, size_t n) {
  if (testrand) {
    assert(n <= sizeof(testrandsrc));
    memcpy(d, testrandsrc, n);
  } else {
    assert(getrandom(d, n, 0) == n);
  }
}

static void TestParseProtobuf() {
  struct ProtobufField fields[6] = {
    [1] = {PB_REQUIRED | PB_UINT32},
    [2] = {PB_REQUIRED | PB_UINT32},
  };
#define FatStrArgs(s) s, (sizeof(s)-1)
  assert(!ParseProtobuf(FatStrArgs("\x08\x01\x10\x80\x01"), fields, 6));
  assert(fields[1].v == 1);
  assert(fields[2].v == 0x80);
  assert(ParseProtobuf(FatStrArgs("\x08\x01\x10\x80\x01")+1, fields, 6));
  assert(ParseProtobuf(FatStrArgs("\x08\x01\x10\x80\x01")-1, fields, 6));
  assert(ParseProtobuf(FatStrArgs("\x08\x01"), fields, 6));
  assert(!ParseProtobuf(FatStrArgs("\x08\x01\x10\x80\x01\x18\x01"), fields, 6));
  assert(fields[3].v == 1);
}

static void TestFormatProtobuf() {
  uint8_t varint[5];
  assert(FormatVarInt(varint, 0) == varint + 1 && varint[0] == 0);
  assert(FormatVarInt(varint, 1) == varint + 1 && varint[0] == 1);
  assert(FormatVarInt(varint, 0x80) == varint + 2 && !memcmp(varint, "\x80\x01", 2));
  assert(FormatVarInt(varint, 0xffffffff) == varint + 5 && !memcmp(varint, "\xff\xff\xff\xff\x0f", 5));
}

static void CopyHex(uint8_t *d, char *hex) {
  int n = strlen(hex);
  assert(n % 2 == 0);
  n /= 2;
  for (int i = 0; i < n; i++) {
    sscanf(hex+(i*2), "%02hhx", d+i);
  }
}

static void TestCurve25519() {
  struct KeyPair kpa, kpb, exp;
  uint8_t shared[32], expshared[32];
  testrand = true;
  CopyHex(testrandsrc, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  CopyHex(exp.prv, "70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a");
  CopyHex(exp.pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  GenerateKeyPair(&kpa);
  assert(!memcmp(exp.prv, kpa.prv, 32));
  assert(!memcmp(exp.pub, kpa.pub, 32));
  CopyHex(testrandsrc, "58ab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b");
  CopyHex(exp.prv, "58ab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b");
  CopyHex(exp.pub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  GenerateKeyPair(&kpb);
  assert(!memcmp(exp.prv, kpb.prv, 32));
  assert(!memcmp(exp.pub, kpb.pub, 32));
  CopyHex(expshared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  CalculateCurveAgreement(shared, kpb.pub, kpa.prv);
  assert(!memcmp(expshared, shared, 32));
  CalculateCurveAgreement(shared, kpa.pub, kpb.prv);
  assert(!memcmp(expshared, shared, 32));
  testrand = false;
}

static void TestSignature() {
  Key prv, pub;
  CurveSignature sig, expsig;
  uint8_t msg[12];
  testrand = true;
  CopyHex(prv, "48a8892cc4e49124b7b57d94fa15becfce071830d6449004685e387"
               "c62409973");
  CopyHex(pub, "55f1bfede27b6a03e0dd389478ffb01462e5c52dbbac32cf870f00a"
               "f1ed9af3a");
  CopyHex(msg, "617364666173646661736466");
  CopyHex(expsig, "2bc06c745acb8bae10fbc607ee306084d0c28e2b3bb819133392"
                  "473431291fd0dfa9c7f11479996cf520730d2901267387e08d85"
                  "bbf2af941590e3035a545285");
  CalculateCurveSignature(sig, prv, msg, 12);
  assert(VerifySignature(expsig, pub, msg, 12));
  assert(VerifySignature(sig, pub, msg, 12));
  memset(sig, 0, 64);
  assert(!VerifySignature(sig, pub, msg, 12));
  testrand = false;
}

static void TestSession() {
  struct KeyPair ida;
  struct PreKey pka;
  struct SignedPreKey spka;
  GenerateKeyPair(&ida);
  GeneratePreKey(&pka, 1337);
  GenerateSignedPreKey(&spka, 1, &ida);

  struct Bundle bundle;
  memcpy(bundle.spks, spka.sig, sizeof(CurveSignature));
  memcpy(bundle.spk, spka.kp.pub, sizeof(PublicKey));
  memcpy(bundle.ik, ida.pub, sizeof(PublicKey));
  memcpy(bundle.pk, pka.kp.pub, sizeof(PublicKey));

  struct Session session;
  assert(ProcessBundle(&session, &bundle) == 0);
}

#define RunTest(t)                                                     \
  do {                                                                 \
    puts("\e[34mRunning test " #t "\e[0m");                            \
    Test##t();                                                         \
    puts("\e[32mFinished test " #t "\e[0m");                           \
  } while (0)

int main() {
  RunTest(ParseProtobuf);
  RunTest(FormatProtobuf);
  RunTest(Curve25519);
  RunTest(Signature);
  RunTest(Session);
  puts("All tests succeeded");
}
