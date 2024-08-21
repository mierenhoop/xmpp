#include "../omemo.c"

#include "c25519.h"

// In the tests we spoof the random source as a hacky way to generate
// the exact private key we want.

void SystemRandom(void *d, size_t n) {
  assert(getrandom(d, n, 0) == n);
}

static void ClearFieldValues(struct ProtobufField *fields, int nfields) {
  for (int i = 0; i < nfields; i++) {
    fields[i].v = 0;
    fields[i].p = NULL;
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
  ClearFieldValues(fields, 6);
  assert(ParseProtobuf(FatStrArgs("\x08\x01\x10\x80\x01")+1, fields, 6));
  ClearFieldValues(fields, 6);
  assert(ParseProtobuf(FatStrArgs("\x08\x01\x10\x80\x01")-1, fields, 6));
  ClearFieldValues(fields, 6);
  assert(ParseProtobuf(FatStrArgs("\x08\x01"), fields, 6));
  ClearFieldValues(fields, 6);
  assert(!ParseProtobuf(FatStrArgs("\x08\x01\x10\x80\x01\x18\x01"), fields, 6));
  assert(fields[3].v == 1);
  memset(fields, 0, sizeof(fields));
  fields[1].type = PB_REQUIRED | PB_LEN;
  fields[2].type = PB_REQUIRED | PB_UINT32;
  assert(!ParseProtobuf(FatStrArgs("\x0a\x04\xcc\xcc\xcc\xcc\x10\x01"), fields, 6));
  assert(fields[1].v == 4);
  assert(fields[1].p && !memcmp(fields[1].p, "\xcc\xcc\xcc\xcc", 4));
  assert(fields[2].v == 1);
  ClearFieldValues(fields, 6);
  assert(ParseProtobuf(FatStrArgs("\x10\x01\x0a\x04\xcc\xcc\xcc"), fields, 6));
  ClearFieldValues(fields, 6);
  fields[1].v = 3;
  assert(!ParseProtobuf(FatStrArgs("\x10\x01\x0a\x03\xcc\xcc\xcc"), fields, 6));
  ClearFieldValues(fields, 6);
  fields[1].v = 2;
  assert(ParseProtobuf(FatStrArgs("\x10\x01\x0a\x03\xcc\xcc\xcc"), fields, 6));
}

static void TestFormatProtobuf() {
  uint8_t varint[6];
  assert(FormatVarInt(varint, 1, 0x00) == varint + 2 && !memcmp(varint, "\x08\x00", 2));
  assert(FormatVarInt(varint, 1, 0x01) == varint + 2 && !memcmp(varint, "\x08\x01", 2));
  assert(FormatVarInt(varint, 1, 0x80) == varint + 3 && !memcmp(varint, "\x08\x80\x01", 3));
  assert(FormatVarInt(varint, 1, 0xffffffff) == varint + 6 && !memcmp(varint, "\x08\xff\xff\xff\xff\x0f", 6));
}

static void CopyHex(uint8_t *d, const char *hex) {
  int n = strlen(hex);
  assert(n % 2 == 0);
  n /= 2;
  for (int i = 0; i < n; i++) {
    sscanf(hex+(i*2), "%02hhx", d+i);
  }
}

static Key base = {9};

static void TestKeyPair(struct KeyPair *kp, const char *rnd, const char *prv, const char *pub) {
  Key kprv, kpub;
  CopyHex(kp->prv, rnd);
  CopyHex(kprv, prv);
  CopyHex(kpub, pub);
  c25519_prepare(kp->prv);
  assert(!memcmp(kp->prv, kprv, 32));
  curve25519_donna(kp->pub, kprv, base);
  assert(!memcmp(kpub, kp->pub, 32));
  memset(kp->pub, 0, 32);
  c25519_smult(kp->pub, c25519_base_x, kprv);
  assert(!memcmp(kpub, kp->pub, 32));
}

static void TestCurve25519() {
  struct KeyPair kpa, kpb, exp;
  uint8_t shared[32], expshared[32], rnd[32];
  TestKeyPair(&kpa, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
  TestKeyPair(&kpb, "58ab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b", "58ab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  CopyHex(expshared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  CalculateCurveAgreement(shared, kpb.pub, kpa.prv);
  assert(!memcmp(expshared, shared, 32));
  CalculateCurveAgreement(shared, kpa.pub, kpb.prv);
  assert(!memcmp(expshared, shared, 32));
}

void crypto_sign_ed25519_ref10_ge_scalarmult_base(void*,const    unsigned char *);
void crypto_sign_ed25519_ref10_ge_p3_tobytes(unsigned char *,void*);

static void MontToEd(Key ed, Key prv) {
  struct {int32_t l[10][4]; } ed_pubkey_point;
  crypto_sign_ed25519_ref10_ge_scalarmult_base(&ed_pubkey_point, prv);
  crypto_sign_ed25519_ref10_ge_p3_tobytes(ed, &ed_pubkey_point);
}

static void ConvertCurvePrvToEdPub(Key ed, const Key prv) {
  struct ed25519_pt p;
  ed25519_smult(&p, &ed25519_base, prv);
  uint8_t x[F25519_SIZE];
  uint8_t y[F25519_SIZE];
  ed25519_unproject(x, y, &p);
  ed25519_pack(ed, x, y);
}

static void c25519_sign(CurveSignature sig, const Key prv, const uint8_t *msg, size_t msgn) {
  assert(msgn <= 33);
  Key ed;
  uint8_t msgbuf[33+64];
  int sign = 0;
  memcpy(msgbuf, msg, msgn);
  SystemRandom(msgbuf+msgn, 64);

  ConvertCurvePrvToEdPub(ed, prv);
  sign = ed[31] & 0x80;

  edsign_sign_modified(sig, ed, prv, msgbuf, 12);

  sig[63] &= 0x7f;
  sig[63] |= sign;
}

static bool c25519_verify(CurveSignature sig, const Key pub, const uint8_t *msg, size_t msgn) {
  Key ed;
  morph25519_mx2ey(ed, pub);
  ed[31] &= 0x7f;
  ed[31] |= sig[63] & 0x80;
  CurveSignature sig2;
  memcpy(sig2, sig, 64);
  sig2[63] &= 0x7f;
  return !!edsign_verify(sig2, ed, msg, msgn);
}

int crypto_sign_modified( unsigned char *sm, const unsigned char *m,unsigned long long mlen, const unsigned char *sk, const unsigned char* pk, const unsigned char* random);

void crypto_sign_ed25519_ref10_sc_muladd(void*,void*,void*,void*);

static void TestSign() {
  CurveSignature sig1, sig2;
  Key prv, pub;
  uint8_t msg[12];
  CopyHex(prv, "48a8892cc4e49124b7b57d94fa15becfce071830d6449004685e387"
               "c62409973");
  CopyHex(pub, "55f1bfede27b6a03e0dd389478ffb01462e5c52dbbac32cf870f00a"
               "f1ed9af3a");
  CopyHex(msg, "617364666173646661736466");
  uint8_t rnd[64];
  memset(rnd, 0xcc, 64);
  Key ed, pp;
  MontToEd(ed, prv);
  ConvertCurvePrvToEdPub(pp, prv);
  uint8_t sigbuf[128], sigbuf2[128];
  crypto_sign_modified(sigbuf, msg, 12, prv, ed, rnd);
  uint8_t msgbuf[100];
  memcpy(msgbuf, msg, 12);
  memset(msgbuf+12, 0xcc, 64);
  edsign_sign_modified(sigbuf2, ed, prv, msgbuf, 12);
  assert(!memcmp(sigbuf, sigbuf2, 64));
}

static void TestSignature() {
  Key prv, pub;
  CurveSignature sig, sig2, expsig;
  uint8_t msg[12], buf[33+128], rnd[64];
  CopyHex(prv, "48a8892cc4e49124b7b57d94fa15becfce071830d6449004685e387"
               "c62409973");
  CopyHex(pub, "55f1bfede27b6a03e0dd389478ffb01462e5c52dbbac32cf870f00a"
               "f1ed9af3a");
  CopyHex(msg, "617364666173646661736466");
  CopyHex(expsig, "2bc06c745acb8bae10fbc607ee306084d0c28e2b3bb819133392"
                  "473431291fd0dfa9c7f11479996cf520730d2901267387e08d85"
                  "bbf2af941590e3035a545285");
  assert(c25519_verify(expsig, pub, msg, 12));
  assert(curve25519_verify(expsig, pub, msg, 12) == 0);

  c25519_sign(sig, prv, msg, 12);
  assert(curve25519_verify(sig, pub, msg, 12) == 0);
  assert(c25519_verify(sig, pub, msg, 12));

  SystemRandom(rnd, 64);
  curve25519_sign(sig, prv, msg, 12, rnd, buf);
  assert(curve25519_verify(sig, pub, msg, 12) == 0);
  assert(c25519_verify(sig, pub, msg, 12));

  memset(sig, 0, 64);
  assert(!c25519_verify(sig, pub, msg, 12));
}

// This would in reality parse the bundle's XML instead of their store.
static void ParseBundle(struct Bundle *bundle, struct Store *store) {
  int pk_id = 42; // Something truly random :)
  memcpy(bundle->spks, store->cursignedprekey.sig, sizeof(CurveSignature));
  memcpy(bundle->spk, store->cursignedprekey.kp.pub, sizeof(Key));
  memcpy(bundle->ik, store->identity.pub, sizeof(Key));
  memcpy(bundle->pk, store->prekeys[pk_id-1].kp.pub, sizeof(Key));
  assert(store->prekeys[pk_id-1].id == 42);
  bundle->pk_id = store->prekeys[pk_id-1].id;
  bundle->spk_id = store->cursignedprekey.id;
}

static void TestEncryption() {
  const uint8_t *msg = "Hello there!";
  size_t n = strlen(msg);
  uint8_t encrypted[100], decrypted[100], iv[12];
  Payload payload;
  EncryptRealMessage(encrypted, payload, iv, msg, n);
  DecryptRealMessage(decrypted, payload, PAYLOAD_SIZE, iv, encrypted, n);
  assert(!memcmp(msg, decrypted, n));
}

struct TestSetup {
  struct Store storea, storeb;
  struct Session sessiona, sessionb;
};

static void MakeTestSetup(struct TestSetup *setup) {
  SetupStore(&setup->storea);
  SetupStore(&setup->storeb);
  struct Bundle bundleb;
  ParseBundle(&bundleb, &setup->storeb);
}

struct Message {
};

static void TestSession() {
  struct Store storea, storeb;
  SetupStore(&storea);
  SetupStore(&storeb);

  struct Bundle bundleb;
  ParseBundle(&bundleb, &storeb);

  struct Session sessiona, sessionb;
  Payload realpayload, payload;
  struct PreKeyMessage msg;
  memset(realpayload, 0xcc, PAYLOAD_SIZE);
  memcpy(payload, realpayload, PAYLOAD_SIZE);
  assert(EncryptFirstMessage(&sessiona, &storea, &bundleb, &msg, payload) == 0);
  memset(payload, 0, PAYLOAD_SIZE);
  assert(msg.n > 0);

  assert(DecryptPreKeyMessage(&sessionb, &storeb, payload, msg.p, msg.n) == 0);
  assert(!memcmp(realpayload, payload, PAYLOAD_SIZE));

  memset(realpayload, 0xdd, PAYLOAD_SIZE);
  memcpy(payload, realpayload, PAYLOAD_SIZE);
  assert(EncryptRatchet(&sessionb, &storeb, &msg, payload) == 0);
  assert(DecryptMessage(&sessiona, &storea, payload, msg.p, msg.n) == 0);
  assert(!memcmp(realpayload, payload, PAYLOAD_SIZE));

  memset(realpayload, 0xee, PAYLOAD_SIZE);
  memcpy(payload, realpayload, PAYLOAD_SIZE);
  assert(EncryptRatchet(&sessionb, &storeb, &msg, payload) == 0);
  assert(DecryptMessage(&sessiona, &storea, payload, msg.p, msg.n) == 0);
  assert(!memcmp(realpayload, payload, PAYLOAD_SIZE));

  memset(realpayload, 0x88, PAYLOAD_SIZE);
  memcpy(payload, realpayload, PAYLOAD_SIZE);
  assert(EncryptRatchet(&sessionb, &storeb, &msg, payload) == 0);

  Payload payload2, realpayload2;
  struct PreKeyMessage msg2;
  memset(realpayload2, 0x77, PAYLOAD_SIZE);
  memcpy(payload2, realpayload2, PAYLOAD_SIZE);
  assert(EncryptRatchet(&sessionb, &storeb, &msg2, payload2) == 0);

  assert(sessiona.mkskipped.n == 0);
  assert(DecryptMessage(&sessiona, &storea, payload2, msg2.p, msg2.n) == 0);
  assert(!memcmp(realpayload2, payload2, PAYLOAD_SIZE));
  assert(sessiona.mkskipped.n == 1);

  assert(DecryptMessage(&sessiona, &storea, payload, msg.p, msg.n) == 0);
  assert(!memcmp(realpayload, payload, PAYLOAD_SIZE));
  assert(sessiona.mkskipped.n == 0);
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
  RunTest(Encryption);
  RunTest(Session);
  RunTest(Sign);
  puts("All tests succeeded");
}
