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
typedef Key EdKey;

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
  //struct SkippedMessageKeys skipped;
};

#define PAYLOAD_SIZE 32
#define HEADER_MAXSIZE (2+33+2*6)
#define FULLMSG_MAXSIZE (1+HEADER_MAXSIZE+2+PAYLOAD_SIZE)
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
};

// As the spec notes, a spk should be kept for one more rotation.
// If prevsignedprekey doesn't exist, its id is 0. Therefore a valid id is always >= 1;
struct Store {
  struct KeyPair identity;
  struct SignedPreKey cursignedprekey, prevsignedprekey;
  struct PreKey prekeys[NUMPREKEYS];
};

// TODO: pack for serialization?
struct Session {
  int fsm;
  Key remoteidentity;
  struct State state;
  struct SkippedMessageKeys mkskipped;
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

int DecryptPreKeyMessage(struct Session *session, struct Store *store, Payload payload, uint8_t *msg, size_t msgn);

#endif
