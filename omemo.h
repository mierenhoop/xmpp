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
#define OMEMO_EALLOC (-9)

typedef uint8_t omemoKey[32];

typedef uint8_t omemoSerializedKey[1+32];
typedef uint8_t omemoCurveSignature[64];

struct omemoKeyPair {
  omemoKey prv;
  omemoKey pub;
};

struct omemoPreKey {
  uint32_t id;
  struct omemoKeyPair kp;
};

struct omemoSignedPreKey {
  uint32_t id;
  struct omemoKeyPair kp;
  omemoCurveSignature sig;
};

struct omemoMessageKey {
  uint32_t nr;
  omemoKey dh;
  omemoKey mk;
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
struct omemoSkippedMessageKeys {
  struct omemoMessageKey *p, *removed;
  size_t n, c, maxskip;
};

struct omemoState {
  struct omemoKeyPair dhs;
  omemoKey dhr;
  omemoKey rk, cks, ckr;
  uint32_t ns, nr, pn;
};

#define OMEMO_PAYLOAD_SIZE 32
#define OMEMO_PAYLOAD_MAXPADDEDSIZE 48
#define OMEMO_HEADER_MAXSIZE (2+33+2*6)
#define OMEMO_FULLMSG_MAXSIZE (1+OMEMO_HEADER_MAXSIZE+2+OMEMO_PAYLOAD_MAXPADDEDSIZE)
#define OMEMO_ENCRYPTED_MAXSIZE (OMEMO_FULLMSG_MAXSIZE+8)
#define OMEMO_PREKEYHEADER_MAXSIZE (1+18+35*2+2)

#define OMEMO_NUMPREKEYS 100

// [        16        |   16  ]
//  GCM encryption key GCM tag
typedef uint8_t omemoPayload[OMEMO_PAYLOAD_SIZE];

struct omemoKeyMessage {
  uint8_t p[OMEMO_PREKEYHEADER_MAXSIZE+OMEMO_ENCRYPTED_MAXSIZE];
  size_t n;
  bool isprekey;
};

// As the spec notes, a spk should be kept for one more rotation.
// If prevsignedprekey doesn't exist, its id is 0. Therefore a valid id is always >= 1;
// pkcounter is the id of the most recently generated prekey.
struct omemoStore {
  bool isinitialized;
  struct omemoKeyPair identity;
  struct omemoSignedPreKey cursignedprekey, prevsignedprekey;
  struct omemoPreKey prekeys[OMEMO_NUMPREKEYS];
  uint32_t pkcounter;
};

struct omemoSession {
  int fsm;
  omemoKey remoteidentity;
  struct omemoState state;
  struct omemoSkippedMessageKeys mkskipped;
  omemoKey pendingek;
  uint32_t pendingpk_id, pendingspk_id;
};

// Random function that must not fail, if the system is not guaranteed
// to always have a random generator available, it should read from a
// pre-filled buffer.
void SystemRandom(void *d, size_t n);
// void SystemRandom(void *d, size_t n) { esp_fill_random(d, n); }

void omemoSerializeKey(omemoSerializedKey k, const omemoKey pub);

struct omemoBundle {
  omemoCurveSignature spks;
  omemoKey spk, ik;
  omemoKey pk; // Randomly selected prekey
  uint32_t pk_id, spk_id;
};

void omemoSetupStore(struct omemoStore *store);
int omemoSetupSession(struct omemoSession *session, size_t cap);
void omemoFreeSession(struct omemoSession *session);

#define omemoIsSessionInitialized(session) (!!(session)->fsm)

int omemoInitFromBundle(struct omemoSession *session, const struct omemoStore *store, const struct omemoBundle *bundle);
int omemoEncryptRatchet(struct omemoSession *session, const struct omemoStore *store, struct omemoKeyMessage *msg, const omemoPayload payload);

int omemoDecryptAnyMessage(struct omemoSession *session, const struct omemoStore *store, omemoPayload payload, bool isprekey, const uint8_t *msg, size_t msgn);

int omemoEncryptRealMessage(uint8_t *d, omemoPayload payload,
                               uint8_t iv[12], const uint8_t *s,
                               size_t n);
int omemoDecryptRealMessage(uint8_t *d, const uint8_t *payload, size_t pn, const uint8_t iv[12], const uint8_t *s, size_t n);

#endif
