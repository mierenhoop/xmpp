#ifndef OMEMO_H_
#define OMEMO_H_

#define OMEMO_EPROTOBUF (-1)
#define OMEMO_ECRYPTO (-2)
#define OMEMO_ECORRUPT (-3)
#define OMEMO_ESIG (-4)
#define OMEMO_ESTATE (-5)
#define OMEMO_ESKIPBUF (-6)
#define OMEMO_EMAXSKIP (-7)
#define OMEMO_EKEYGONE (-8)

typedef uint8_t Key[32];

typedef uint8_t SerializedKey[1+32];
typedef uint8_t CurveSignature[64];

struct KeyPair {
  Key prv;
  Key pub;
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
  uint32_t nr;
  Key dh;
  Key mk;
};

// p is a pointer to the array of message keys with capacity c.
// the array contains n entries.
// When the array is full and you don't want to allocate more space you
// can remove the old entries and reduce n.
// removed is NULL before calling a decryption function. When a message
// has been decrypted AND a skipped message key is used, removed will
// point to that key in array p. After this happens, it is the task of
// the API consumer to remove the key from the array and move the
// contents so that the array doesn't contain holes.
// c >= maxskip
struct SkippedMessageKeys {
  struct MessageKey _data[2000]; // TODO: remove
  struct MessageKey *p, *removed;
  size_t n, c, maxskip;
};

struct State {
  struct KeyPair dhs;
  Key dhr;
  Key rk, cks, ckr;
  uint32_t ns, nr, pn;
};

#define PAYLOAD_SIZE 32
#define PAYLOAD_MAXPADDEDSIZE 48
#define HEADER_MAXSIZE (2+33+2*6)
#define FULLMSG_MAXSIZE (1+HEADER_MAXSIZE+2+PAYLOAD_MAXPADDEDSIZE)
#define ENCRYPTED_MAXSIZE (FULLMSG_MAXSIZE+8)
#define PREKEYHEADER_MAXSIZE (1+18+35*2+2)

#define NUMPREKEYS 100

// [        16        |   16  ]
//  GCM encryption key GCM tag
typedef uint8_t Payload[PAYLOAD_SIZE];

// TODO: GenericMessage? we could reuse this for normal OMEMOMessages, they just don't include the PreKey header.
struct PreKeyMessage {
  uint8_t p[PREKEYHEADER_MAXSIZE+ENCRYPTED_MAXSIZE];
  size_t n;
  bool isprekey;
};

// As the spec notes, a spk should be kept for one more rotation.
// If prevsignedprekey doesn't exist, its id is 0. Therefore a valid id is always >= 1;
// pkcounter is the id of the most recently generated prekey.
struct Store {
  struct KeyPair identity;
  struct SignedPreKey cursignedprekey, prevsignedprekey;
  struct PreKey prekeys[NUMPREKEYS];
  uint32_t pkcounter;
};

// TODO: pack for serialization?
struct Session {
  int fsm;
  Key remoteidentity;
  struct State state;
  struct SkippedMessageKeys mkskipped;
  Key pendingek;
  uint32_t pendingpk_id, pendingspk_id;
};

// Random function that must not fail, if the system is not guaranteed
// to always have a random generator available, it should read from a
// pre-filled buffer.
void SystemRandom(void *d, size_t n);
// void SystemRandom(void *d, size_t n) { esp_fill_random(d, n); }

void SerializeKey(SerializedKey k, const Key pub);

struct Bundle {
  CurveSignature spks;
  Key spk, ik;
  Key pk; // Randomly selected prekey
  uint32_t pk_id, spk_id;
};

void SetupStore(struct Store *store);

#define IsSessionInitialized(session) (!!(session)->fsm)

int InitFromBundle(struct Session *session, const struct Store *store, const struct Bundle *bundle);
int EncryptRatchet(struct Session *session, const struct Store *store, struct PreKeyMessage *msg, const Payload payload);

int DecryptPreKeyMessage(struct Session *session, const struct Store *store, Payload payload, const uint8_t *msg, size_t msgn);

int DecryptAnyMessage(struct Session *session, const struct Store *store, Payload payload, bool isprekey, const uint8_t *msg, size_t msgn);

int DecryptMessage(struct Session *session, const struct Store *store, Payload decrypted, const uint8_t *msg, size_t msgn);

void EncryptRealMessage(uint8_t *d, Payload payload,
                               uint8_t iv[12], const uint8_t *s,
                               size_t n);
void DecryptRealMessage(uint8_t *d, const uint8_t *payload, size_t pn, const uint8_t iv[12], const uint8_t *s, size_t n);

#endif
