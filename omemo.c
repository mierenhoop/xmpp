// TODO: we should remove the dep on mbedtls here since it creates
// points of failures that wouldn't be there with other crypto
// implementations (mostly from heap allocation).
#include <mbedtls/hkdf.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>

#include <sys/random.h>

#include "curve25519.h"
#include "c25519.h"

#include "omemo.h"

#define SESSION_UNINIT 0
#define SESSION_INIT 1
#define SESSION_READY 2

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
    //if (i > 32 - 7) // will overflow
    //  return NULL;
  } while (*s++ & 0x80);
  return s;
}

// ParseProtobuf parses string `s` with length `n` containing Protobuf
// data. For each field encountered it does the following:
// - Make sure the field number can be stored in `fields` and that the
//   type corresponds with the one specified in the associated field.
// - Mark the field number as found which later will be used to check whether
//   all required fields are found.
// - Parse the value.
// - If there already is a non-zero value specified in the field, it is
//   used to check whether the parsed value is the same.
// `nfields` is the amount of fields in the `fields` array. It should have the value of the highest possible
// field number + 1. `nfields` must be less than or equal to 16 because
// we only support a single byte field number, the number is stored like
// this in the byte: 0nnnnttt where n is the field number and t is the
// type.
static int ParseProtobuf(const uint8_t *s, size_t n,
                         struct ProtobufField *fields, int nfields) {
  int type, id;
  uint32_t v;
  const uint8_t *e = s + n;
  uint32_t found = 0;
  assert(nfields <= 16);
  while (s < e) {
    // This is actually a varint, but we only support id < 16 and return
    // an error otherwise, so we don't have to account for multiple-byte
    // tags.
    type = *s & 7;
    id = *s >> 3;
    s++;
    if (id >= nfields || type != (fields[id].type & 7))
      return OMEMO_EPROTOBUF;
    found |= 1 << id;
    if (!(s = ParseVarInt(s, e, &v)))
      return OMEMO_EPROTOBUF;
    if (fields[id].v && v != fields[id].v)
      return OMEMO_EPROTOBUF;
    fields[id].v = v;
    if (type == PB_LEN) {
      fields[id].p = s;
      s += fields[id].v;
    }
  }
  if (s > e)
    return OMEMO_EPROTOBUF;
  for (int i = 0; i < nfields; i++) {
    if ((fields[i].type & PB_REQUIRED) && !(found & (1 << i)))
      return OMEMO_EPROTOBUF;
  }
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

// sizeof(d) >= 2+n
/*static uint8_t *FormatBytes(uint8_t *d, int id, uint8_t *b, int n) {
  assert(id < 16 && n < 128);
  *d++ = (id << 3) | PB_LEN;
  *d++ = n;
  memcpy(d, b, n);
  return d + n;
}*/

static uint8_t *FormatKey(uint8_t *d, int id, Key k) {
  assert(id < 16);
  *d++ = (id << 3) | PB_LEN;
  *d++ = 33;
  *d++ = 0x05;
  memcpy(d, k, 32);
  return d + 32;
}

// PreKeyWhisperMessage without message (it should be appended right after this call)
// ek = basekey
static size_t FormatPreKeyMessage(uint8_t d[PREKEYHEADER_MAXSIZE], uint32_t pk_id, uint32_t spk_id, Key ik, Key ek, uint32_t msgsz) {
  assert(msgsz < 128);
  uint8_t *p = d;
  *p++ = (3 << 4) | 3; // (message->version << 4) | CIPHERTEXT_CURRENT_VERSION
  p = FormatVarInt(p, 5, 0xcc); // TODO: registration id
  p = FormatVarInt(p, 1, pk_id);
  p = FormatVarInt(p, 6, spk_id);
  p = FormatKey(p, 3, ik);
  p = FormatKey(p, 2, ek);
  *p++ = (4 << 3) | PB_LEN;
  *p++ = msgsz;
  return p - d;
}

// WhisperMessage without ciphertext
// HEADER(dh_pair, pn, n)
static size_t FormatMessageHeader(uint8_t d[HEADER_MAXSIZE], uint32_t n, uint32_t pn, Key dhs) {
  uint8_t *p = d;
  *p++ = (3 << 4) | 3; // (message->version << 4) | CIPHERTEXT_CURRENT_VERSION
  p = FormatKey(p, 1, dhs);
  p = FormatVarInt(p, 2, n);
  return FormatVarInt(p, 3, pn) - d;
}

static void NormalizeSkipMessageKeysTrivial(struct SkippedMessageKeys *s) {
  assert(s->p && s->n <= s->c);
  if (s->removed) {
    assert(s->p <= s->removed && s->removed < s->p + s->n);
    size_t n = s->n - (s->removed - s->p) - 1;
    memmove(s->removed, s->removed + 1, n * sizeof(struct SkippedMessageKeys));
    s->n--;
    s->removed = NULL;
  }
}


static void DumpHex(const uint8_t *p, int n, const char *msg) {
  for (int i=0;i<n;i++)
    printf("%02x", p[i]);
  printf(" << %s\n", msg);
}

static const uint8_t basepoint[32] = {9};

static void GenerateKeyPair(struct KeyPair *kp) {
  memset(kp, 0, sizeof(*kp));
  SystemRandom(kp->prv, sizeof(kp->prv));
  c25519_prepare(kp->prv);
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

void SerializeKey(SerializedKey k, const Key pub) {
  k[0] = 5;
  memcpy(k + 1, pub, sizeof(SerializedKey) - 1);
}

static void CalculateCurveSignature(CurveSignature cs, Key signprv, uint8_t *msg, size_t n) {
  // TODO: OMEMO uses xed25519 and old libsignal uses curve25519
  assert(n <= 33);
  uint8_t rnd[sizeof(CurveSignature)], buf[33+128];
  SystemRandom(rnd, sizeof(rnd));
  // TODO: change this function so it doesn't fail, n will always be 33, so we will need to allocate buffer of 33+128 and pass it.
  //assert(xed25519_sign(cs, signprv, msg, n, rnd) >= 0);
  curve25519_sign(cs, signprv, msg, n, rnd, buf);
}

// AKA ECDHE
static void CalculateCurveAgreement(uint8_t d[static 32],
                                    const Key pub,
                                    Key prv) {

  curve25519_donna(d, prv, pub);
}

static void GenerateSignedPreKey(struct SignedPreKey *spk, uint32_t id,
                                 struct KeyPair *idkp) {
  SerializedKey ser;
  spk->id = id;
  GenerateKeyPair(&spk->kp);
  SerializeKey(ser, spk->kp.pub);
  CalculateCurveSignature(spk->sig, idkp->prv, ser,
                          sizeof(SerializedKey));
}

static bool VerifySignature(CurveSignature sig, Key sk,
                            const uint8_t *msg, size_t n) {
  return curve25519_verify(sig, sk, msg, n) == 0;
}

void SetupStore(struct Store *store) {
  memset(store, 0, sizeof(struct Store));
  GenerateIdentityKeyPair(&store->identity);
  DumpHex(store->identity.pub, 32, "ikpub");
  DumpHex(store->identity.prv, 32, "ikprv");
  GenerateSignedPreKey(&store->cursignedprekey, 1, &store->identity);
  DumpHex(store->cursignedprekey.kp.pub, 32, "spkpub");
  DumpHex(store->cursignedprekey.kp.prv, 32, "spkprv");
  DumpHex(store->cursignedprekey.sig, 64, "spksig");
  for (int i = 0; i < NUMPREKEYS; i++) {
    GeneratePreKey(store->prekeys+i, i+1);
    printf("id %d\n", i+1);
    DumpHex(store->prekeys[i].kp.pub, 32, "pkpub");
    DumpHex(store->prekeys[i].kp.prv, 32, "pkprv");
  }
}

static void SetupSession(struct Session *session) {
  memset(session, 0, sizeof(struct Session));
  session->mkskipped.p = session->mkskipped._data;
  session->mkskipped.c = 2000;
  session->mkskipped.maxskip = 1000;
}

// AD = Encode(IKA) || Encode(IKB)
static void GetAd(uint8_t ad[66], const Key ika, const Key ikb) {
  SerializeKey(ad, ika);
  SerializeKey(ad + 33, ikb);
}

static int GetMac(uint8_t d[static 8], const Key ika, const Key ikb, const Key mk, const uint8_t *msg, size_t msgn) {
  assert(msgn <= FULLMSG_MAXSIZE);
  uint8_t macinput[66+FULLMSG_MAXSIZE], mac[32];
  GetAd(macinput, ika, ikb);
  memcpy(macinput+66, msg, msgn);
  if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), mk, 32, macinput, 66+msgn, mac) != 0)
    return OMEMO_ECRYPTO;
  memcpy(d, mac, 8);
  return 0;
}

static void Encrypt(Payload out, const Payload in, Key key,
                    uint8_t iv[static 16]) {
  mbedtls_aes_context aes;
  // These functions won't fail, so we can skip error checking.
  assert(mbedtls_aes_setkey_enc(&aes, key, 256) == 0);
  assert(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 32,
                               iv, in, out) == 0);
}

static void Decrypt(Payload out, const Payload in, Key key,
                    uint8_t iv[static 16]) {
  mbedtls_aes_context aes;
  assert(mbedtls_aes_setkey_dec(&aes, key, 256) == 0);
  assert(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 32,
                               iv, in, out) == 0);
  DumpHex(out, PAYLOAD_SIZE, "decrypted");
}

struct __attribute__((__packed__)) DeriveChainKeyOutput {
  Key ck, mk; // TODO: rename mk to mac, it's not a message key
  uint8_t iv[16];
};
_Static_assert(sizeof(struct DeriveChainKeyOutput) == 80);

static int DeriveChainKey(struct DeriveChainKeyOutput *out, const Key ck) {
  uint8_t salt[32];
  memset(salt, 0, 32);
  return mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                      salt, 32, ck, sizeof(Key), "WhisperMessageKeys",
                      18, (uint8_t *)out,
                      sizeof(struct DeriveChainKeyOutput))
             ? OMEMO_ECRYPTO
             : 0;
}

// TODO: rename to GetBaseMaterials
static int KDF_CK(Key d, Key mac, const Key ck) {
  Key tmp;
  uint8_t data = 1;
  if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), ck, 32, &data, 1, mac) != 0)
    return OMEMO_ECRYPTO;
  data = 2;
  if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), ck, 32, &data, 1, tmp) != 0)
    return OMEMO_ECRYPTO;
  memcpy(d, tmp, 32);
  return 0;
}

// CKs, mk = KDF_CK(CKs)
// header = HEADER(DHs, PN, Ns)
// Ns += 1
// return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
// macinput      [   33   |   33   |   1   | <=46 |2|PAYLOAD_SIZE]
//                identity identity version header    encrypted   mac[:8]
// msg->p                          [^^^^^^^^^^^^^^^^^^^^^^^^^^^^^|   8   ]
// TODO: remove store? we only need public ik, we can put that in session
static int EncryptRatchetImpl(struct Session *session, struct Store *store, struct PreKeyMessage *msg, Payload payload) {
  Key mk;
  struct DeriveChainKeyOutput kdfout;
  assert(KDF_CK(session->state.cks, mk, session->state.cks) == 0);
  DumpHex(mk, 32, "encrypt mk");
  if (DeriveChainKey(&kdfout, mk))
    return OMEMO_ECRYPTO;

  msg->n = FormatMessageHeader(msg->p, session->state.ns, session->state.pn, session->state.dhs.pub);
  msg->p[msg->n++] = (4 << 3) | PB_LEN;
  msg->p[msg->n++] = PAYLOAD_MAXPADDEDSIZE;
  Encrypt(msg->p+msg->n, payload, kdfout.ck, kdfout.iv);
  memset(msg->p+msg->n+32, 0x10, 0x10);
  msg->n += PAYLOAD_MAXPADDEDSIZE;

  if (GetMac(msg->p+msg->n, store->identity.pub, session->remoteidentity, kdfout.mk, msg->p, msg->n))
    return -1;
  msg->n += 8;

  session->state.ns++;
  return 0;
}

static int EncryptRatchet(struct Session *session, struct Store *store, struct PreKeyMessage *msg, Payload payload) {
  int r;
  struct State backup;
  memcpy(&backup, &session->state, sizeof(struct State));
  if ((r = EncryptRatchetImpl(session, store, msg, payload))) {
    memcpy(&session->state, &backup, sizeof(struct State));
    memset(msg, 0, sizeof(struct PreKeyMessage));
  }
  return r;
}

// RK, ck = KDF_RK(RK, DH(DHs, DHr))
static int DeriveRootKey(struct State *state, Key ck) {
  uint8_t secret[32], masterkey[64];
  CalculateCurveAgreement(secret, state->dhr, state->dhs.prv);
  if (mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                      state->rk, sizeof(Key), secret, sizeof(secret),
                      "WhisperRatchet", 14, masterkey, 64) != 0)
    return OMEMO_ECRYPTO;
  memcpy(state->rk, masterkey, sizeof(Key));
  memcpy(ck, masterkey + 32, 32);
  return 0;
}


// DH1 = DH(IKA, SPKB)
// DH2 = DH(EKA, IKB)
// DH3 = DH(EKA, SPKB)
// DH4 = DH(EKA, OPKB)
// SK = KDF(DH1 || DH2 || DH3 || DH4)
static int GetSharedSecret(Key sk, bool isbob, Key ika, Key ska, Key eka, const Key ikb, const Key spkb, const Key opkb) {
  uint8_t secret[32*5] = {0}, salt[32];
  memset(secret, 0xff, 32);
  // When we are bob, we must swap the first two.
  CalculateCurveAgreement(secret+32, isbob ? ikb : spkb, isbob ? ska : ika);
  CalculateCurveAgreement(secret+64, isbob ? spkb : ikb, isbob ? ika : ska);
  CalculateCurveAgreement(secret+96, spkb, ska);
  // OMEMO mandates that the bundle MUST contain a prekey.
  CalculateCurveAgreement(secret+128, opkb, eka);
  memset(salt, 0, 32);
  if (mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, 32, secret, sizeof(secret), "WhisperText", 11, sk, 32) != 0)
    return OMEMO_ECRYPTO;
  DumpHex(sk, 32, "shared secret");
  uint8_t full[64];
  if (mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, 32, secret, sizeof(secret), "WhisperText", 11, full, 64) != 0)
    return OMEMO_ECRYPTO;
  DumpHex(full+32, 32, "full");
  return 0;
}

// state.DHs = GENERATE_DH()
// state.DHr = bob_dh_public_key
// state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr)) 
// state.CKr = None
// state.Ns = 0
// state.Nr = 0
// state.PN = 0
// state.MKSKIPPED = {}
// TODO: when we are sending a prekeymessage a second time, we should not regenerate the dhs (ek), so we must not call RatchetInitAlice again...
static int RatchetInitAlice(struct State *state, Key sk, Key ekb) {
  memset(state, 0, sizeof(struct State));
  GenerateKeyPair(&state->dhs);
  memcpy(state->rk, sk, 32);
  memcpy(state->dhr, ekb, 32);
  if (DeriveRootKey(state, state->cks))
    return OMEMO_ECRYPTO;
  return 0;
}

// When we process the bundle, we are the ones who initialize the
// session and we are referred to as alice. Otherwise we have received
// an initiation message and are called bob.
// session is initialized in this function
// msg->payload contains the payload that will be encrypted into msg->encrypted with size msg->encryptedsz (when this function returns 0)
static int EncryptFirstMessage(struct Session *session, struct Store *store, struct Bundle *bundle, struct PreKeyMessage *msg, Payload payload) {
  int r;
  SerializedKey serspk;
  SetupSession(session);
  SerializeKey(serspk, bundle->spk);
  if (!VerifySignature(bundle->spks, bundle->ik, serspk, sizeof(SerializedKey))) {
     return OMEMO_ESIG;
  }
  struct KeyPair eka;
  GenerateKeyPair(&eka);
  memset(&session->state, 0, sizeof(struct State));
  memcpy(session->remoteidentity, bundle->ik, sizeof(Key));
  Key sk;
  if ((r = GetSharedSecret(sk, false, store->identity.prv, eka.prv, eka.prv, bundle->ik, bundle->spk, bundle->pk)))
    return r;
  RatchetInitAlice(&session->state, sk, bundle->spk);
  if ((r = EncryptRatchet(session, store, msg, payload)))
    return r;
  if (session->fsm != SESSION_READY) {
    // [message 00...] -> [00... message] -> [header 00... message] -> [header message]
    memmove(msg->p+PREKEYHEADER_MAXSIZE, msg->p, msg->n);
    int headersz = FormatPreKeyMessage(msg->p, bundle->pk_id, bundle->spk_id, store->identity.pub, eka.pub, msg->n);
    memmove(msg->p+headersz, msg->p+PREKEYHEADER_MAXSIZE, msg->n);
    msg->n += headersz;
  }
  session->fsm = SESSION_INIT;
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
static int DHRatchet(struct State *state, const Key dh) {
  int r;
  state->pn = state->ns;
  state->ns = 0;
  state->nr = 0;
  memcpy(state->dhr, dh, 32);
  if ((r = DeriveRootKey(state, state->ckr)))
    return r;
  DumpHex(state->rk, 32, "new rootkey");
  DumpHex(state->ckr, 32, "new ckr");
  GenerateKeyPair(&state->dhs);
  if ((r = DeriveRootKey(state, state->cks)))
    return r;
  DumpHex(state->rk, 32, "new rootkey");
  DumpHex(state->cks, 32, "new cks");
  return 0;
}

static void RatchetInitBob(struct State *state, Key sk, struct KeyPair *ekb) {
  memcpy(&state->dhs, ekb, sizeof(struct KeyPair));
  memcpy(state->rk, sk, 32);
}

static struct MessageKey *FindMessageKey(struct SkippedMessageKeys *keys, const Key dh, uint32_t n) {
  for (int i = 0; i < keys->n; i++) {
    if (keys->p[i].nr == n && !memcmp(dh, keys->p[i].dh, 32)) {
      return keys->p + i;
    }
  }
  return NULL;
}

static void SkipMessageKeys(struct State *state, struct SkippedMessageKeys *keys, uint32_t n) {
  assert(keys->n + (n - state->nr) <= keys->c); // this is checked in DecryptMessage
  while (state->nr < n) {
    Key mk;
    assert(KDF_CK(state->ckr, mk, state->ckr) == 0);
    keys->p[keys->n].nr = state->nr;
    memcpy(keys->p[keys->n].dh, state->dhr, 32);
    memcpy(keys->p[keys->n].mk, mk, 32);
    keys->n++;
    state->nr++;
  }
}

static int DecryptMessageImpl(struct Session *session, struct Store *store, Payload decrypted, const uint8_t *msg, size_t msgn) {
  int r;
  if (session->fsm != SESSION_INIT && session->fsm != SESSION_READY)
    return OMEMO_ESTATE;
  if (msgn < 9 || msg[0] != ((3 << 4) | 3))
    return OMEMO_ECORRUPT;
  struct ProtobufField fields[5] = {
    [1] = {PB_REQUIRED | PB_LEN, 33}, // ek
    [2] = {PB_REQUIRED | PB_UINT32}, // n
    [3] = {PB_REQUIRED | PB_UINT32}, // pn
    [4] = {PB_REQUIRED | PB_LEN}, // ciphertext
  };
  DumpHex(msg+1, msgn-9, "PB");

  if ((r = ParseProtobuf(msg+1, msgn-9, fields, 5)))
    return r;
  // We accept non-padded or correctly PKCS#7 padded.
  // TODO: when v == 32, last 16 bytes are padded too, so the payload is only 16 bytes?
  if (!(fields[4].v == 32 ||
        (fields[4].v == 48 &&
         !memcmp(fields[4].p + 32,
                 "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", 0x10))))
    return OMEMO_ECORRUPT;
  // these checks should already be handled by ParseProtobuf, just to make sure...
  assert(fields[1].v == 33);

  uint32_t headern = fields[2].v;
  uint32_t headerpn = fields[3].v;
  const uint8_t *headerdh = fields[1].p+1;

  DumpHex(headerdh, 32, "headerdh");

  bool shouldstep = !!memcmp(session->state.dhr, headerdh, 32);

  // We first check for maxskip, if that does not pass we should not
  // process the message. If it does pass, we know the total capacity of
  // the array is large enough because c >= maxskip. Then we check if the
  // new keys fit in the remaining space. If that is not the case we
  // return and let the user either remove the old message keys or ignore
  // the message.

  Key mk;
  struct MessageKey *key;
  if ((key = FindMessageKey(&session->mkskipped, headerdh, headern))) {
    memcpy(mk, key->mk, 32);
    session->mkskipped.removed = key;
  } else {
    if (!shouldstep && headern < session->state.nr) return OMEMO_EKEYGONE;
    if (shouldstep && headerpn < session->state.nr) return OMEMO_EKEYGONE;
    uint64_t nskips = shouldstep ?
      headerpn - session->state.nr + headern :
      headern - session->state.nr;
    if (nskips > session->mkskipped.maxskip) return OMEMO_EMAXSKIP;
    if (nskips > session->mkskipped.c - session->mkskipped.n) return OMEMO_ESKIPBUF;
    if (shouldstep) {
      SkipMessageKeys(&session->state, &session->mkskipped, headerpn);
      if ((r = DHRatchet(&session->state, headerdh)))
        return r;
    }
    SkipMessageKeys(&session->state, &session->mkskipped, headern);
    assert(KDF_CK(session->state.ckr, mk, session->state.ckr) == 0);
    DumpHex(session->state.ckr, 32, "new ckr");
    DumpHex(mk, 32, "decrypt mk");
    session->state.nr++;
  }
  struct DeriveChainKeyOutput kdfout;
  assert(DeriveChainKey(&kdfout, mk) == 0);
  DumpHex(kdfout.ck, 32, "derived ck");
  DumpHex(kdfout.mk, 32, "derived mk (mackey)");
  DumpHex(kdfout.iv, 16, "derived iv");
  uint8_t mac[8];
  DumpHex(session->remoteidentity, 32, "remote ik");
  DumpHex(store->identity.pub, 32, "our ik");
  assert(GetMac(mac, session->remoteidentity, store->identity.pub, kdfout.mk, msg, msgn-8) == 0);
  DumpHex(mac, 8, "genmac");
  DumpHex(msg+msgn-8, 8, "realmac");
  if (memcmp(mac, msg+msgn-8, 8))
    return OMEMO_ECORRUPT;
  Decrypt(decrypted, fields[4].p, kdfout.ck, kdfout.iv);
  session->fsm = SESSION_READY;
  return 0;
}

static int DecryptMessage(struct Session *session, struct Store *store, Payload decrypted, const uint8_t *msg, size_t msgn) {
  int r;
  assert(session && session->mkskipped.p && !session->mkskipped.removed);
  assert(store);
  struct State backup;
  uint32_t mkskippednbackup = session->mkskipped.n;
  memcpy(&backup, &session->state, sizeof(struct State));
  if ((r = DecryptMessageImpl(session, store, decrypted, msg, msgn))) {
    memcpy(&session->state, &backup, sizeof(struct State));
    memset(decrypted, 0, PAYLOAD_SIZE);
    session->mkskipped.n = mkskippednbackup;
    session->mkskipped.removed = NULL;
  }
  if (session->mkskipped.removed)
    NormalizeSkipMessageKeysTrivial(&session->mkskipped);
  return r;
}

// Decrypt the (usually) first message and start/initialize a session.
// TODO: the prekey message can be sent multiple times, what should we do then?
static int DecryptPreKeyMessageImpl(struct Session *session, struct Store *store, Payload payload, uint8_t *p, uint8_t* e) {
  int r;
  if (e-p == 0 || *p++ != ((3 << 4) | 3))
    return OMEMO_ECORRUPT;
  // PreKeyWhisperMessage
  struct ProtobufField fields[7] = {
    [5] = {PB_REQUIRED | PB_UINT32}, // registrationid
    [1] = {PB_REQUIRED | PB_UINT32}, // prekeyid
    [6] = {PB_REQUIRED | PB_UINT32}, // signedprekeyid
    [2] = {PB_REQUIRED | PB_LEN, 33}, // basekey/ek
    [3] = {PB_REQUIRED | PB_LEN, 33}, // identitykey/ik
    [4] = {PB_REQUIRED | PB_LEN}, // message
  };
  if ((r = ParseProtobuf(p, e-p, fields, 7)))
    return r;
  assert(fields[2].v == 33);
  assert(fields[3].v == 33);
  // later remove this prekey
  struct PreKey *pk = FindPreKey(store, fields[1].v);
  if (!pk)
    return OMEMO_ECORRUPT;
  struct SignedPreKey *spk = FindSignedPreKey(store, fields[6].v);
  if (!spk)
    return OMEMO_ECORRUPT;
  memcpy(session->remoteidentity, fields[3].p+1, sizeof(Key));
  printf("pkid %d\n", fields[1].v);
  DumpHex(pk->kp.prv, 32, "pkprv");
  DumpHex(pk->kp.pub, 32, "pkpub");

  printf("spkid %d\n", fields[6].v);
  DumpHex(spk->kp.prv, 32, "spkprv");
  DumpHex(spk->kp.pub, 32, "spkpub");

  Key sk;
  if ((r = GetSharedSecret(sk, true, store->identity.prv, spk->kp.prv, pk->kp.prv, fields[3].p+1, fields[2].p+1, fields[2].p+1)))
    return r;
  RatchetInitBob(&session->state, sk, &spk->kp);

  session->fsm = SESSION_READY;
  return DecryptMessage(session, store, payload, fields[4].p, fields[4].v);
}

int DecryptPreKeyMessage(struct Session *session, struct Store *store, Payload payload, uint8_t *msg, size_t msgn) {
  SetupSession(session);
  int r;
  if ((r = DecryptPreKeyMessageImpl(session, store, payload, msg, msg+msgn))) {
    memset(session, 0, sizeof(struct Session));
    memset(payload, 0, PAYLOAD_SIZE);
    return r;
  }
  return 0;
}

// pn is size of payload, some clients might make the tag larger than 16 bytes.
static void DecryptRealMessage(uint8_t *d, const uint8_t *payload, size_t pn, const uint8_t iv[12], const uint8_t *s, size_t n) {
  assert(pn >= 32);
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  assert(!mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, payload, 128));
  assert(!mbedtls_gcm_auth_decrypt(&ctx, n, iv, 12, "", 0, payload+16, pn-16, s, d));
  mbedtls_gcm_free(&ctx);
}

// payload and iv are outputs
// Both d and s have size n
static void EncryptRealMessage(uint8_t *d, Payload payload,
                               uint8_t iv[12], const uint8_t *s,
                               size_t n) {
  SystemRandom(payload, 16);
  SystemRandom(iv, 12);
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  assert(!mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, payload, 128));
  assert(!mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, n, iv, 12, "", 0, s, d, 16, payload+16));
  mbedtls_gcm_free(&ctx);
}

static void SerializeSession(uint8_t *d, struct Session *session) {
  memcpy(d, &session->state, sizeof(struct State));
  d += sizeof(struct State);
  for (int i = 0; i < session->mkskipped.n; i++) {
    memcpy(d, &session->mkskipped.p+i, sizeof(struct MessageKey));
    d += sizeof(struct MessageKey);
  }
  // TODO: message keys and crc?
}
