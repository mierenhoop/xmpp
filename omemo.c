#include <mbedtls/hkdf.h>
#include <mbedtls/aes.h>

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>

#include <sys/random.h>

#include "curve25519.h"

static const uint8_t basepoint[32] = {9};

typedef uint8_t Key[32];
// TODO: we can just use Key for everthing
typedef Key PrivateKey;
typedef Key PublicKey;
typedef Key EdKey;
// struct IdentityKey {PublicKey pub; EdKey ed; };
typedef uint8_t SerializedKey[1+32];
typedef uint8_t CurveSignature[64];

struct KeyPair {
  PrivateKey prv;
  PublicKey pub;
};

struct PreKey {
  uint32_t id;
  struct KeyPair kp;
};

struct SignedPreKey {
  uint32_t id;
  struct KeyPair kp;
  CurveSignature sig;
};

struct MessageKey {
  bool exists;
  uint32_t nr;
  Key dh;
  Key mk;
};

struct State {
  struct KeyPair dhs;
  PublicKey dhr;
  Key rk, cks, ckr;
  uint32_t ns, nr, pn;
  struct MessageKey skipped[2000]; // TODO: make this a ring buffer
};

#define PAYLOAD_SIZE 32
#define HEADER_MAXSIZE (2+32+2*6)
#define FULLMSG_MAXSIZE (1+HEADER_MAXSIZE+2+PAYLOAD_SIZE)
#define ENCRYPTED_MAXSIZE (FULLMSG_MAXSIZE+8)
#define PREKEYHEADER_MAXSIZE (1+18+34*2+2)

#define NUMPREKEYS 100

// As the spec notes, a spk should be kept for one more rotation.
// If prevsignedprekey doesn't exist, its id is 0. Therefore a valid id is always >= 1;
struct Store {
  struct KeyPair identity;
  struct SignedPreKey cursignedprekey, prevsignedprekey;
  struct PreKey prekeys[NUMPREKEYS];
};

// TODO: pack for serialization?
struct Session {
  int flags;
  PublicKey remoteidentity;
  struct State state;
  struct Store *store;
  bool dontsendprekeys;
};

struct EncryptedMessage {
  uint8_t payload[PAYLOAD_SIZE];
  uint8_t encrypted[PREKEYHEADER_MAXSIZE+ENCRYPTED_MAXSIZE];
  size_t encryptedsz;
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
  uint32_t pk_id, spk_id;
  //PublicKey prekeys[150];
  //size_t prekeysn;
};

// Protobuf: https://protobuf.dev/programming-guides/encoding/

// Only supports uint32 and len prefixed (by int32).
struct ProtobufField {
  int type;
  uint32_t v;
  const uint8_t *p;
};

#define PB_REQUIRED (1 << 3)
#define PB_UINT32 0
#define PB_LEN 2

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

static int ParseProtobuf(const uint8_t *s, size_t n, struct ProtobufField *fields, int nfields) {
  int type, id;
  uint32_t v;
  const uint8_t *e = s + n;
  uint32_t found = 0;
  assert(nfields <= 16);
  while (s < e) {
    // This is actually a varint, but we only support id < 16 and return an
    // error otherwise, so we don't have to account for multiple-byte tags.
    type = *s & 7;
    id = *s >> 3;
    s++;
    if (id >= nfields || type != (fields[id].type & 7))
      return -1;
    found |= 1 << id;
    if (!(s = ParseVarInt(s, e, &v)))
      return -1;
    //if (fields[id].v && v != fields[id].v)
    //  return -1;
    fields[id].v = v;
    if (type == PB_LEN) {
      fields[id].p = s;
      s += fields[id].v;
    }
  }
  if (s > e)
    return -1;
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

static uint8_t *FormatVarInt(uint8_t d[static 6], int id, uint32_t v) {
  assert(id < 16);
  *d++ = (id << 3) | PB_UINT32;
  do {
    *d = v & 0x7f;
    v >>= 7;
    *d++ |= (!!v << 7);
  } while (v);
  return d;
}

// sizeof(d) == 2+n
static uint8_t *FormatBytes(uint8_t *d, int id, uint8_t *b, int n) {
  assert(id < 16 && n < 128);
  *d++ = (id << 3) | PB_LEN;
  *d++ = n;
  memcpy(d, b, n);
  return d + n;
}

// PreKeyWhisperMessage without message (it should be appended right after this call)
// ek = basekey
static uint8_t *FormatPreKeyMessage(uint8_t d[PREKEYHEADER_MAXSIZE], uint32_t pk_id, uint32_t spk_id, PublicKey ik, PublicKey ek, uint32_t msgsz) {
  assert(msgsz < 128);
  *d++ = (3 << 4) | 3; // (message->version << 4) | CIPHERTEXT_CURRENT_VERSION
  d = FormatVarInt(d, 5, 0xcc); // TODO: registration id
  d = FormatVarInt(d, 1, pk_id);
  d = FormatVarInt(d, 6, spk_id);
  d = FormatBytes(d, 3, ik, sizeof(PublicKey));
  d = FormatBytes(d, 2, ek, sizeof(PublicKey));
  *d++ = (4 << 3) | PB_LEN;
  *d++ = msgsz;
  return d;
}

// WhisperMessage without ciphertext
// HEADER(dh_pair, pn, n)
static uint8_t *FormatMessageHeader(uint8_t d[HEADER_MAXSIZE], uint32_t n, uint32_t pn, PublicKey dhs) {
  *d++ = (3 << 4) | 3; // (message->version << 4) | CIPHERTEXT_CURRENT_VERSION
  d = FormatBytes(d, 1, dhs, sizeof(PublicKey));
  d = FormatVarInt(d, 2, n);
  return FormatVarInt(d, 3, pn);
}

static void DumpHex(const uint8_t *p, int n, const char *msg) {
  for (int i=0;i<n;i++)
    printf("%02x", p[i]);
  printf(" << %s\n", msg);
}

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

static int CalculateCurveSignature(CurveSignature cs, Key signprv, uint8_t *msg, size_t n) {
  // TODO: OMEMO uses xed25519 and old libsignal uses curve25519
  assert(n <= 33);
  uint8_t rnd[sizeof(CurveSignature)], buf[33+128];
  SystemRandom(rnd, sizeof(rnd));
  // TODO: change this function so it doesn't fail, n will always be 33, so we will need to allocate buffer of 33+128 and pass it.
  //assert(xed25519_sign(cs, signprv, msg, n, rnd) >= 0);
  assert(curve25519_sign(cs, signprv, msg, n, rnd) >= 0);
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
static void CalculateCurveAgreement(uint8_t d[static 32], const PublicKey pub, PrivateKey prv) {
  curve25519_donna(d, prv, pub);
}

static void GenerateSignedPreKey(struct SignedPreKey *spk, uint32_t id, struct KeyPair *idkp) {
  SerializedKey ser;
  spk->id = id;
  GenerateKeyPair(&spk->kp);
  SerializeKey(ser, spk->kp.pub);
  CalculateCurveSignature(spk->sig, idkp->prv, ser, sizeof(SerializedKey));
}

static bool VerifySignature(CurveSignature sig, PublicKey sk, const uint8_t *msg, size_t n) {
  return curve25519_verify(sig, sk, msg, n) == 0;
}

// AD = Encode(IKA) || Encode(IKB)
static void GetAd(uint8_t ad[66], Key ika, Key ikb) {
  SerializeKey(ad, ika);
  SerializeKey(ad+33, ikb);
}

static void Encrypt(uint8_t out[static PAYLOAD_SIZE], const uint8_t in[static PAYLOAD_SIZE], Key key, uint8_t iv[static 16]) {
  mbedtls_aes_context aes;
  assert(mbedtls_aes_setkey_enc(&aes, key, 256) == 0);
  assert(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, PAYLOAD_SIZE, iv, in, out) == 0);
}

static void Decrypt(uint8_t out[static PAYLOAD_SIZE], const uint8_t in[static PAYLOAD_SIZE], Key key, uint8_t iv[static 16]) {
  mbedtls_aes_context aes;
  assert(mbedtls_aes_setkey_dec(&aes, key, 256) == 0);
  assert(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, PAYLOAD_SIZE, iv, in, out) == 0);
}

// TODO: we don't actually have to pack this right?
struct __attribute__((__packed__)) DeriveChainKeyOutput  {
  Key ck, mk;
  uint8_t iv[16];
};
_Static_assert(sizeof(struct DeriveChainKeyOutput) == 80);

static void DeriveChainKey(struct DeriveChainKeyOutput *out, Key ck) {
  uint8_t salt[32];
  memset(salt, 0, 32);
  assert(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                      salt, 32, ck, sizeof(Key), "WhisperMessageKeys",
                      18, (uint8_t *)out,
                      sizeof(struct DeriveChainKeyOutput)) == 0);
}

// What this function would do in libomemo-c is get the identity keypair
// from a callback and memcpy everything.
//static void GetIdentityKeyPair(struct KeyPair *ouridkeypair) {
//  PublicKey pub;
//  PrivateKey prv;
//  // TODO: check if it's always plain pub key and not ed or Serialized
//  DecodePointMont(pub, ouridkeypair->pub);
//  DecodePrivatePoint(prv, ouridkeypair->prv);
//}

// CKs, mk = KDF_CK(CKs)
// header = HEADER(DHs, PN, Ns)
// Ns += 1
// return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
// macinput      [   33   |   33   |   1   | <=46 |2|PAYLOAD_SIZE]
//                identity identity version header    encrypted   mac[:8]
// msg->encrypted                  [^^^^^^^^^^^^^^^^^^^^^^^^^^^^^|   8   ]
// TODO: keep sending prekeymessages until we receive something
static void EncryptRatchet(struct Session *session, struct EncryptedMessage *msg) {
  uint8_t macinput[33*2+FULLMSG_MAXSIZE], mac[32], encrypted[PAYLOAD_SIZE];
  DumpHex(session->state.cks, 32, "cks");
  struct DeriveChainKeyOutput kdfout;
  DeriveChainKey(&kdfout, session->state.cks);

  GetAd(macinput, session->store->identity.pub, session->remoteidentity);
  int n = FormatMessageHeader(macinput+66, session->state.ns, session->state.pn, session->state.dhs.pub) - macinput;

  DumpHex(msg->payload, PAYLOAD_SIZE, "plaintext");

  DumpHex(kdfout.ck, 32, "encrypt ck");
  DumpHex(kdfout.ck, 16, "encrypt iv");
  Encrypt(encrypted, msg->payload, kdfout.ck, kdfout.iv);
  DumpHex(encrypted, PAYLOAD_SIZE, "encrypted");
  // TODO: we should inline this function, size is constant anyways
  n = FormatBytes(macinput+n, 4, encrypted, PAYLOAD_SIZE) - macinput;

  int encsz = n - 33*2;
  memcpy(msg->encrypted, macinput+33*2, encsz);
  assert(mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), kdfout.mk, 32, macinput, n, mac) == 0);
  memcpy(msg->encrypted+encsz, mac, 8);
  msg->encryptedsz = encsz + 8;

  // nothing can fail anymore so we save the new state
  session->state.ns++;
  memcpy(session->state.cks, kdfout.ck, 32);
}

// RK, CKs = KDF_RK(SK, DH(DHs, DHr))
static void DeriveRootKey(struct State *state, Key rk, Key ck) {
  uint8_t secret[32], masterkey[64];
  CalculateCurveAgreement(secret, state->dhr, state->dhs.prv);
  assert(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), state->rk, sizeof(Key), secret, sizeof(secret), "WhisperRatchet", 14, masterkey, 64) == 0);
  memcpy(rk, masterkey, sizeof(Key));
  memcpy(ck, masterkey+32, 32);
}

// DH1 = DH(IKA, SPKB)
// DH2 = DH(EKA, IKB)
// DH3 = DH(EKA, SPKB)
// DH4 = DH(EKA, OPKB)
// SK = KDF(DH1 || DH2 || DH3 || DH4)
static void GetSharedSecret(Key sk, bool isbob, Key ika, Key ska, Key eka, const Key ikb, const Key spkb, const Key opkb) {
  uint8_t secret[32*5] = {0}, salt[32];
  memset(secret, 0xff, 32);
  // When we are bob, we must swap the first two.
  isbob = !!isbob;
  CalculateCurveAgreement(secret+32+32*isbob, spkb, ika);
  CalculateCurveAgreement(secret+64-32*isbob, ikb, ska);
  CalculateCurveAgreement(secret+96, spkb, ska);
  // OMEMO mandates that the bundle MUST contain a prekey.
  CalculateCurveAgreement(secret+128, opkb, eka);
  for (int i = 32; i < 32*5; i+=32)
    DumpHex(secret+i, 32, " << secret");
  memset(salt, 0, 32);
  assert(mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, 32, secret, sizeof(secret), "WhisperText", 11, sk, 32) == 0);
}

// state.DHs = GENERATE_DH()
// state.DHr = bob_dh_public_key
// state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr)) 
// state.CKr = None
// state.Ns = 0
// state.Nr = 0
// state.PN = 0
// state.MKSKIPPED = {}
static void RatchetInitAlice(struct State *state, Key sk, Key ekb) {
  memset(state, 0, sizeof(struct State));
  GenerateKeyPair(&state->dhs);
  memcpy(state->rk, sk, 32);
  memcpy(state->dhr, ekb, 32);
  DeriveRootKey(state, state->rk, state->cks);
}

// When we process the bundle, we are the ones who initialize the
// session and we are referred to as alice. Otherwise we have received
// an initiation message and are called bob.
// session is initialized in this function
// msg->payload contains the payload that will be encrypted into msg->encrypted with size msg->encryptedsz (when this function returns 0)
static int ProcessBundle(struct Session *s, struct Store *store, struct Bundle *b, struct EncryptedMessage *msg) {
  SerializedKey serspk;
  memset(s, 0, sizeof(struct Session));
  s->store = store;
  SerializeKey(serspk, b->spk);
  if (!VerifySignature(b->spks, b->ik, serspk, sizeof(SerializedKey))) {
     return -1;
  }
  struct KeyPair eka;
  GenerateKeyPair(&eka);
  memset(&s->state, 0, sizeof(struct State));
  memcpy(s->remoteidentity, b->ik, sizeof(PublicKey));
  Key sk;
  GetSharedSecret(sk, false, s->store->identity.prv, eka.prv, eka.prv, b->ik, b->spk, b->pk);
  DumpHex(sk, 32, "alice sk");
  DumpHex(s->store->identity.pub, 32, "alice ik");
  DumpHex(eka.pub, 32, "alice ek");
  DumpHex(b->ik, 32, "bob ik");
  DumpHex(b->spk, 32, "bob spk");
  DumpHex(b->pk, 32, "bob pk");
  RatchetInitAlice(&s->state, sk, b->pk);
  EncryptRatchet(s, msg);
  if (!s->dontsendprekeys) {
    // [message 00...] -> [00... message] -> [header 00... message] -> [header message]
    memmove(msg->encrypted+PREKEYHEADER_MAXSIZE, msg->encrypted, msg->encryptedsz);
    int headersz = FormatPreKeyMessage(msg->encrypted, b->pk_id, b->spk_id, s->store->identity.pub, eka.pub, msg->encryptedsz) - msg->encrypted;
    memmove(msg->encrypted+headersz, msg->encrypted+PREKEYHEADER_MAXSIZE, msg->encryptedsz);
    msg->encryptedsz += headersz;
  }

  return 0;
}

static struct PreKey *FindPreKey(struct Store *store, uint32_t pk_id) {
  for (int i = 0; i < NUMPREKEYS; i++) {
    if (store->prekeys[i].id == pk_id)
      return store->prekeys+i;
  }
  return NULL;
}

static struct SignedPreKey *FindSignedPreKey(struct Store *store, uint32_t spk_id) {
  if (spk_id == 0)
    return NULL;
  if (store->cursignedprekey.id == spk_id)
    return &store->cursignedprekey;
  if (store->prevsignedprekey.id == spk_id)
    return &store->prevsignedprekey;
  return NULL;
}

static inline uint32_t IncrementWrapSkipZero(uint32_t n) {
  n++;
  return n + !n;
}

static void RotateSignedPreKey(struct Store *store) {
  memcpy(&store->prevsignedprekey, &store->cursignedprekey,
         sizeof(struct SignedPreKey));
  GenerateSignedPreKey(
      &store->cursignedprekey,
      IncrementWrapSkipZero(store->prevsignedprekey.id),
      &store->identity);
}

// PN = Ns
// Ns = 0
// Nr = 0
// DHr = dh
// RK, CKr = KDF_RK(RK, DH(DHs, DHr))
// DHs = GENERATE_DH()
// RK, CKs = KDF_RK(RK, DH(DHs, DHr))
static void DHRatchet(struct Session *session, const Key dh) {
  session->state.pn = session->state.ns;
  session->state.ns = 0;
  session->state.nr = 0;
  memcpy(session->state.dhr, dh, 32);
  DeriveRootKey(&session->state, session->state.rk, session->state.ckr);
  GenerateKeyPair(&session->state.dhs);
  DeriveRootKey(&session->state, session->state.rk, session->state.cks);
}

static void RatchetInitBob(struct State *state, Key sk, struct KeyPair *ekb) {
  memcpy(&state->dhs, ekb, sizeof(struct KeyPair));
  memcpy(state->rk, sk, 32);
}

static void DecryptMessage(struct Session *session, uint8_t decrypted[PAYLOAD_SIZE], const uint8_t *p, const uint8_t *e) {
  assert(e-p > 0 && *p++ == ((3 << 4) | 3));
  assert(e-p >= 8);
  e -= 8;
  const uint8_t *mac = e;
  struct ProtobufField fields[5] = {
    [1] = {PB_REQUIRED | PB_LEN}, // ek
    [2] = {PB_REQUIRED | PB_UINT32}, // n
    [3] = {PB_REQUIRED | PB_UINT32}, // pn
    [4] = {PB_REQUIRED | PB_LEN}, // ciphertext
  };

  assert(!ParseProtobuf(p, e-p, fields, 5));
  assert(fields[1].v == 32); // TODO: put size check in ParseProtobuf?
  // if (!(state->session.state & SESSION_INITIALIZED))

  DHRatchet(session, fields[1].p);

  DumpHex(session->state.cks, 32, "cks");
  uint8_t macinput[33*2+FULLMSG_MAXSIZE];

  struct DeriveChainKeyOutput kdfout;
  DeriveChainKey(&kdfout, session->state.ckr);
  memcpy(session->state.ckr, kdfout.ck, 32);

  GetAd(macinput, session->store->identity.pub, session->remoteidentity);
  int n = FormatMessageHeader(macinput+66, session->state.ns, session->state.pn, session->state.dhs.pub) - macinput;

  assert(fields[4].v == PAYLOAD_SIZE);
  DumpHex(kdfout.ck, 32, "decrypt ck");
  DumpHex(kdfout.ck, 16, "decrypt iv");
  DumpHex(fields[4].p, PAYLOAD_SIZE, "encrypted");
  Decrypt(decrypted, fields[4].p, kdfout.ck, kdfout.iv);
  DumpHex(decrypted, PAYLOAD_SIZE, "decrypted");
  session->state.nr++;
}

// msg->encrypted contains the payload with size msg->encryptedsz that will be decrypted into msg->payload (when this function returns 0)
static void ProcessPreKeyMessage(struct Session *session, struct Store *store, struct EncryptedMessage *msg) {
  uint8_t *p = msg->encrypted;
  uint8_t *e = p+msg->encryptedsz;
  assert(e-p > 0 && *p++ == ((3 << 4) | 3));
  memset(session, 0, sizeof(struct Session));
  session->store = store;
  // PreKeyWhisperMessage
  struct ProtobufField fields[7] = {
    [5] = {PB_REQUIRED | PB_UINT32}, // registrationid
    [1] = {PB_REQUIRED | PB_UINT32}, // prekeyid
    [6] = {PB_REQUIRED | PB_UINT32}, // signedprekeyid
    [2] = {PB_REQUIRED | PB_LEN}, // basekey
    [3] = {PB_REQUIRED | PB_LEN}, // identitykey
    [4] = {PB_REQUIRED | PB_LEN}, // message
  };
  assert(ParseProtobuf(p, e-p, fields, 7) == 0);
  // if () return -1;
  // later remove this prekey
  struct PreKey *pk = FindPreKey(session->store, fields[1].v);
  // if (!pk) return -1;
  assert(pk);
  struct SignedPreKey *spk = FindSignedPreKey(session->store, fields[6].v);
  // if (!spk) return -1;
  assert(spk);

  //Key basekey;
  assert(fields[2].v == sizeof(Key));
  //memcpy(basekey, fields[2].p, sizeof(Key));
  assert(fields[3].v == sizeof(Key));
  memcpy(session->remoteidentity, fields[3].p, sizeof(Key));

  Key sk;
  GetSharedSecret(sk, true, session->store->identity.prv, spk->kp.prv, pk->kp.prv, fields[3].p, fields[2].p, fields[2].p);
  DumpHex(sk, 32, "bob sk");
  DumpHex(session->store->identity.pub, 32, "bob ik");
  DumpHex(spk->kp.pub, 32, "bob spk");
  DumpHex(pk->kp.pub, 32, "bob ek");
  DumpHex(fields[3].p, 32, "alice ik");
  DumpHex(fields[2].p, 32, "alice ek");
  //DumpHex(spk->kp.prv, 32, "bob sk");
  //DumpHex(pk->kp.prv, 32, "bob sk");
  //DumpHex(fields[3].p, 32, "bob sk");
  //DumpHex(fields[2].p, 32, "bob sk");
  RatchetInitBob(&session->state, sk, &pk->kp);

  DecryptMessage(session, msg->payload, fields[4].p, fields[4].p+fields[4].v);
}
