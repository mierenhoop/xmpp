#include "../omemo.c"

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
  struct KeyPair idb;
  struct PreKey pkb;
  struct SignedPreKey spkb;
  GenerateKeyPair(&idb);
  GeneratePreKey(&pkb, 1337);
  GenerateSignedPreKey(&spkb, 1, &idb);

  struct Bundle bundleb;
  memcpy(bundleb.spks, spkb.sig, sizeof(CurveSignature));
  memcpy(bundleb.spk, spkb.kp.pub, sizeof(PublicKey));
  memcpy(bundleb.ik, idb.pub, sizeof(PublicKey));
  memcpy(bundleb.pk, pkb.kp.pub, sizeof(PublicKey));

  struct Session sessiona;
  struct EncryptedMessage msg;
  memset(msg.payload, 0xcc, PAYLOAD_SIZE);
  assert(ProcessBundle(&sessiona, &bundleb, &msg) == 0);
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
