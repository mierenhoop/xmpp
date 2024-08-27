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

// Parse Protobuf varint. Only supports uint32, higher bits are skipped
// so it will neither overflow nor clamp to UINT32_MAX.
static const uint8_t *ParseVarInt(const uint8_t *s, const uint8_t *e, uint32_t *v) {
  int i = 0;
  *v = 0;
  do {
    if (s >= e)
      return NULL;
    *v |= (*s & 0x7f) << i;
    i += 7;
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

void SerializeKey(SerializedKey k, const Key pub) {
  k[0] = 5;
  memcpy(k + 1, pub, sizeof(SerializedKey) - 1);
}

static uint8_t *FormatKey(uint8_t *d, int id, const Key k) {
  assert(id < 16);
  *d++ = (id << 3) | PB_LEN;
  *d++ = 33;
  SerializeKey(d, k);
  return d + 33;
}

// Format Protobuf PreKeyWhisperMessage without message (it should be
// appended right after this call).
static size_t FormatPreKeyMessage(uint8_t d[PREKEYHEADER_MAXSIZE],
                                  uint32_t pk_id, uint32_t spk_id,
                                  const Key ik, const Key ek,
                                  uint32_t msgsz) {
  assert(msgsz < 128);
  uint8_t *p = d;
  *p++ = (3 << 4) | 3;
  p = FormatVarInt(p, 5, 0xcc); // TODO: registration id
  p = FormatVarInt(p, 1, pk_id);
  p = FormatVarInt(p, 6, spk_id);
  p = FormatKey(p, 3, ik);
  p = FormatKey(p, 2, ek);
  *p++ = (4 << 3) | PB_LEN;
  *p++ = msgsz;
  return p - d;
}

// Format Protobuf WhisperMessage without ciphertext.
//  HEADER(dh_pair, pn, n)
static size_t FormatMessageHeader(uint8_t d[HEADER_MAXSIZE], uint32_t n,
                                  uint32_t pn, const Key dhs) {
  uint8_t *p = d;
  *p++ = (3 << 4) | 3;
  p = FormatKey(p, 1, dhs);
  p = FormatVarInt(p, 2, n);
  return FormatVarInt(p, 3, pn) - d;
}

// Remove the skipped message key that has just been used for
// decrypting.
//  del state.MKSKIPPED[header.dh, header.n]
static void
NormalizeSkipMessageKeysTrivial(struct SkippedMessageKeys *s) {
  assert(s->p && s->n <= s->c);
  if (s->removed) {
    assert(s->p <= s->removed && s->removed < s->p + s->n);
    size_t n = s->n - (s->removed - s->p) - 1;
    memmove(s->removed, s->removed + 1,
            n * sizeof(struct SkippedMessageKeys));
    s->n--;
    s->removed = NULL;
  }
}


static void DumpHex(const uint8_t *p, int n, const char *msg) {
  for (int i=0;i<n;i++)
    printf("%02x", p[i]);
  printf(" << %s\n", msg);
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
  edsign_sign_modified(sig, ed, prv, msgbuf, msgn);
  sig[63] &= 0x7f;
  sig[63] |= sign;
}

static bool c25519_verify(const CurveSignature sig, const Key pub, const uint8_t *msg, size_t msgn) {
  Key ed;
  morph25519_mx2ey(ed, pub);
  ed[31] &= 0x7f;
  ed[31] |= sig[63] & 0x80;
  CurveSignature sig2;
  memcpy(sig2, sig, 64);
  sig2[63] &= 0x7f;
  return !!edsign_verify(sig2, ed, msg, msgn);
}

static const uint8_t basepoint[32] = {9};

static void GenerateKeyPair(struct KeyPair *kp) {
  memset(kp, 0, sizeof(*kp));
  SystemRandom(kp->prv, sizeof(kp->prv));
  c25519_prepare(kp->prv);
  c25519_smult(kp->pub, c25519_base_x, kp->prv);
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

static void CalculateCurveSignature(CurveSignature sig, Key signprv,
                                    uint8_t *msg, size_t n) {
  assert(n <= 33);
  uint8_t rnd[sizeof(CurveSignature)], buf[33 + 128];
  SystemRandom(rnd, sizeof(rnd));
  c25519_sign(sig, signprv, msg, n);
}

//  DH(dh_pair, dh_pub)
static void CalculateCurveAgreement(uint8_t d[static 32], const Key prv,
                                    const Key pub) {

  c25519_smult(d, pub, prv);
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

//  Sig(PK, M)
static bool VerifySignature(const CurveSignature sig, const Key sk,
                            const uint8_t *msg, size_t n) {
  return c25519_verify(sig, sk, msg, n);
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

//  AD = Encode(IKA) || Encode(IKB)
static void GetAd(uint8_t ad[66], const Key ika, const Key ikb) {
  SerializeKey(ad, ika);
  SerializeKey(ad + 33, ikb);
}

static int GetMac(uint8_t d[static 8], const Key ika, const Key ikb,
                  const Key mk, const uint8_t *msg, size_t msgn) {
  assert(msgn <= FULLMSG_MAXSIZE);
  uint8_t macinput[66 + FULLMSG_MAXSIZE], mac[32];
  GetAd(macinput, ika, ikb);
  memcpy(macinput + 66, msg, msgn);
  if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), mk,
                      32, macinput, 66 + msgn, mac) != 0)
    return OMEMO_ECRYPTO;
  memcpy(d, mac, 8);
  return 0;
}

static void Encrypt(uint8_t out[PAYLOAD_MAXPADDEDSIZE], const Payload in, Key key,
                    uint8_t iv[static 16]) {
  _Static_assert(PAYLOAD_MAXPADDEDSIZE == 48);
  uint8_t tmp[48];
  memcpy(tmp, in, 32);
  memset(tmp+32, 0x10, 0x10);
  mbedtls_aes_context aes;
  // These functions won't fail, so we can skip error checking.
  assert(mbedtls_aes_setkey_enc(&aes, key, 256) == 0);
  assert(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 48,
                               iv, tmp, out) == 0);
}

static void Decrypt(uint8_t *out, const uint8_t *in, size_t n, Key key,
                    uint8_t iv[static 16]) {
  mbedtls_aes_context aes;
  assert(mbedtls_aes_setkey_dec(&aes, key, 256) == 0);
  assert(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, n,
                               iv, in, out) == 0);
  DumpHex(out, PAYLOAD_SIZE, "decrypted");
}

struct __attribute__((__packed__)) DeriveChainKeyOutput {
  Key cipher, mac;
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

// d may be the same pointer as ck
//  ck, mk = KDF_CK(ck)
static int GetBaseMaterials(Key d, Key mk, const Key ck) {
  Key tmp;
  uint8_t data = 1;
  if (mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), ck, 32, &data, 1, mk) != 0)
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
// msg->p                          [^^^^^^^^^^^^^^^^^^^^^^^^^^^^^|   8   ]
static int EncryptRatchetImpl(struct Session *session, const struct Store *store, struct PreKeyMessage *msg, const Payload payload) {
  int r;
  Key mk;
  struct DeriveChainKeyOutput kdfout;
  if ((r = GetBaseMaterials(session->state.cks, mk, session->state.cks)))
    return r;
  DumpHex(mk, 32, "encrypt mk");
  if ((r = DeriveChainKey(&kdfout, mk)))
    return r;

  msg->n = FormatMessageHeader(msg->p, session->state.ns, session->state.pn, session->state.dhs.pub);
  msg->p[msg->n++] = (4 << 3) | PB_LEN;
  msg->p[msg->n++] = PAYLOAD_MAXPADDEDSIZE;
  Encrypt(msg->p+msg->n, payload, kdfout.cipher, kdfout.iv);
  msg->n += PAYLOAD_MAXPADDEDSIZE;

  if ((r = GetMac(msg->p+msg->n, store->identity.pub, session->remoteidentity, kdfout.mac, msg->p, msg->n)))
    return r;
  msg->n += 8;

  session->state.ns++;
  return 0;
}

int EncryptRatchet(struct Session *session, const struct Store *store, struct PreKeyMessage *msg, const Payload payload) {
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
  CalculateCurveAgreement(secret, state->dhs.prv, state->dhr);
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
static int GetSharedSecret(Key sk, bool isbob, const Key ika, const Key ska, const Key eka, const Key ikb, const Key spkb, const Key opkb) {
  uint8_t secret[32*5] = {0}, salt[32];
  memset(secret, 0xff, 32);
  // When we are bob, we must swap the first two.
  CalculateCurveAgreement(secret+32, isbob ? ska : ika, isbob ? ikb : spkb);
  CalculateCurveAgreement(secret+64, isbob ? ika : ska, isbob ? spkb : ikb);
  CalculateCurveAgreement(secret+96, ska, spkb);
  // OMEMO mandates that the bundle MUST contain a prekey.
  CalculateCurveAgreement(secret+128, eka, opkb);
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

//  state.DHs = GENERATE_DH()
//  state.DHr = bob_dh_public_key
//  state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr)) 
//  state.CKr = None
//  state.Ns = 0
//  state.Nr = 0
//  state.PN = 0
//  state.MKSKIPPED = {}
// TODO: when we are sending a prekeymessage a second time, we should not regenerate the dhs (ek), so we must not call RatchetInitAlice again...
static int RatchetInitAlice(struct State *state, const Key sk, const Key ekb) {
  memset(state, 0, sizeof(struct State));
  GenerateKeyPair(&state->dhs);
  memcpy(state->rk, sk, 32);
  memcpy(state->dhr, ekb, 32);
  if (DeriveRootKey(state, state->cks))
    return OMEMO_ECRYPTO;
  return 0;
}

// The session is initialized in this function if no error is returned.
int EncryptFirstMessage(struct Session *session,
                        const struct Store *store,
                        const struct Bundle *bundle,
                        struct PreKeyMessage *msg,
                        const Payload payload) {
  int r;
  SerializedKey serspk;
  SetupSession(session);
  SerializeKey(serspk, bundle->spk);
  if (!VerifySignature(bundle->spks, bundle->ik, serspk,
                       sizeof(SerializedKey))) {
    return OMEMO_ESIG;
  }
  struct KeyPair eka;
  GenerateKeyPair(&eka);
  memset(&session->state, 0, sizeof(struct State));
  memcpy(session->remoteidentity, bundle->ik, sizeof(Key));
  Key sk;
  if ((r = GetSharedSecret(sk, false, store->identity.prv, eka.prv,
                           eka.prv, bundle->ik, bundle->spk,
                           bundle->pk)))
    return r;
  if ((r = RatchetInitAlice(&session->state, sk, bundle->spk)))
    return r;
  if ((r = EncryptRatchet(session, store, msg, payload)))
    return r;
  if (session->fsm != SESSION_READY) {
    // [message 00...] -> [00... message] -> [header 00... message] ->
    // [header message]
    memmove(msg->p + PREKEYHEADER_MAXSIZE, msg->p, msg->n);
    int headersz =
        FormatPreKeyMessage(msg->p, bundle->pk_id, bundle->spk_id,
                            store->identity.pub, eka.pub, msg->n);
    memmove(msg->p + headersz, msg->p + PREKEYHEADER_MAXSIZE, msg->n);
    msg->n += headersz;
  }
  session->fsm = SESSION_INIT;
  return 0;
}

static const struct PreKey *FindPreKey(const struct Store *store, uint32_t pk_id) {
  for (int i = 0; i < NUMPREKEYS; i++) {
    if (store->prekeys[i].id == pk_id)
      return store->prekeys+i;
  }
  return NULL;
}

static const struct SignedPreKey *FindSignedPreKey(const struct Store *store, uint32_t spk_id) {
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

//  PN = Ns
//  Ns = 0
//  Nr = 0
//  DHr = dh
//  RK, CKr = KDF_RK(RK, DH(DHs, DHr))
//  DHs = GENERATE_DH()
//  RK, CKs = KDF_RK(RK, DH(DHs, DHr))
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

static void RatchetInitBob(struct State *state, const Key sk, const struct KeyPair *ekb) {
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

static int SkipMessageKeys(struct State *state, struct SkippedMessageKeys *keys, uint32_t n) {
  int r;
  assert(keys->n + (n - state->nr) <= keys->c); // this is checked in DecryptMessage
  while (state->nr < n) {
    Key mk;
    if ((r = GetBaseMaterials(state->ckr, mk, state->ckr)))
      return r;
    keys->p[keys->n].nr = state->nr;
    memcpy(keys->p[keys->n].dh, state->dhr, 32);
    memcpy(keys->p[keys->n].mk, mk, 32);
    keys->n++;
    state->nr++;
  }
  return 0;
}

static int DecryptMessageImpl(struct Session *session,
                              const struct Store *store,
                              Payload decrypted, const uint8_t *msg,
                              size_t msgn) {
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
  // these checks should already be handled by ParseProtobuf, just to make sure...
  if (fields[4].v > 48 || fields[4].v < 32)
    return OMEMO_ECORRUPT;
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
      if ((r = SkipMessageKeys(&session->state, &session->mkskipped, headerpn)))
        return r;
      if ((r = DHRatchet(&session->state, headerdh)))
        return r;
    }
    if ((r = SkipMessageKeys(&session->state, &session->mkskipped, headern)))
      return r;
    if ((r = GetBaseMaterials(session->state.ckr, mk, session->state.ckr)))
      return r;
    DumpHex(session->state.ckr, 32, "new ckr");
    DumpHex(mk, 32, "decrypt mk");
    session->state.nr++;
  }
  struct DeriveChainKeyOutput kdfout;
  if ((r = DeriveChainKey(&kdfout, mk)))
    return r;
  DumpHex(kdfout.cipher, 32, "derived ck");
  DumpHex(kdfout.mac, 32, "derived mk (mackey)");
  DumpHex(kdfout.iv, 16, "derived iv");
  uint8_t mac[8];
  DumpHex(session->remoteidentity, 32, "remote ik");
  DumpHex(store->identity.pub, 32, "our ik");
  if ((r = GetMac(mac, session->remoteidentity, store->identity.pub, kdfout.mac, msg, msgn-8)))
    return r;
  DumpHex(mac, 8, "genmac");
  DumpHex(msg+msgn-8, 8, "realmac");
  if (memcmp(mac, msg+msgn-8, 8))
    return OMEMO_ECORRUPT;
  uint8_t tmp[48];
  Decrypt(tmp, fields[4].p, fields[4].v, kdfout.cipher, kdfout.iv);
  memcpy(decrypted, tmp, 32);
  session->fsm = SESSION_READY;
  return 0;
}

int DecryptMessage(struct Session *session, const struct Store *store, Payload decrypted, const uint8_t *msg, size_t msgn) {
  int r;
  assert(session && session->mkskipped.p && !session->mkskipped.removed);
  assert(store);
  assert(msg);
  struct State backup;
  uint32_t mkskippednbackup = session->mkskipped.n;
  memcpy(&backup, &session->state, sizeof(struct State));
  if ((r = DecryptMessageImpl(session, store, decrypted, msg, msgn))) {
    memcpy(&session->state, &backup, sizeof(struct State));
    memset(decrypted, 0, PAYLOAD_SIZE);
    session->mkskipped.n = mkskippednbackup;
    session->mkskipped.removed = NULL;
    return r;
  }
  if (session->mkskipped.removed)
    NormalizeSkipMessageKeysTrivial(&session->mkskipped);
  return 0;
}

// Decrypt the (usually) first message and start/initialize a session.
// TODO: the prekey message can be sent multiple times, what should we do then?
static int DecryptPreKeyMessageImpl(struct Session *session, const struct Store *store, Payload payload, const uint8_t *p, const uint8_t* e) {
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
  const struct PreKey *pk = FindPreKey(store, fields[1].v);
  if (!pk)
    return OMEMO_ECORRUPT;
  const struct SignedPreKey *spk = FindSignedPreKey(store, fields[6].v);
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
  // TODO: we could also call DecryptMessageImpl in this case.
  return DecryptMessage(session, store, payload, fields[4].p, fields[4].v);
}

int DecryptPreKeyMessage(struct Session *session, const struct Store *store, Payload payload, const uint8_t *msg, size_t msgn) {
  assert(store);
  assert(msg && msgn);
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
void DecryptRealMessage(uint8_t *d, const uint8_t *payload, size_t pn, const uint8_t iv[12], const uint8_t *s, size_t n) {
  assert(pn >= 32);
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  assert(!mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, payload, 128));
  assert(!mbedtls_gcm_auth_decrypt(&ctx, n, iv, 12, "", 0, payload+16, pn-16, s, d));
  mbedtls_gcm_free(&ctx);
}

// payload and iv are outputs
// Both d and s have size n
void EncryptRealMessage(uint8_t *d, Payload payload,
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

static void SerializeStore(uint8_t d[static sizeof(struct Store)], const struct Store *store) {
  memcpy(d, store, sizeof(struct Store));
}

static void DeserializeStore(struct Store *store, uint8_t s[static sizeof(struct Store)]) {
  memcpy(store, s, sizeof(struct Store));
}

// TODO: use Protobuf for this.
static void SerializeSession(uint8_t *d, struct Session *session) {
  memcpy(d, &session->state, sizeof(struct State));
  d += sizeof(struct State);
  for (int i = 0; i < session->mkskipped.n; i++) {
    memcpy(d, &session->mkskipped.p+i, sizeof(struct MessageKey));
    d += sizeof(struct MessageKey);
  }
  // TODO: message keys and crc?
}
