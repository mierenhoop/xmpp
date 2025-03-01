/**
 * Copyright 2024 mierenhoop
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef OMEMO_H_
#define OMEMO_H_

#include <stdint.h>
#include <stdbool.h>

#define OMEMO_NUMPREKEYS 100

#define OMEMO_EPROTOBUF (-1)
#define OMEMO_ECRYPTO (-2)
#define OMEMO_ECORRUPT (-3)
#define OMEMO_ESIG (-4)
#define OMEMO_ESTATE (-5)
#define OMEMO_ESKIPBUF (-6)
#define OMEMO_EMAXSKIP (-7)
#define OMEMO_EKEYGONE (-8)
#define OMEMO_EALLOC (-9)
#define OMEMO_EUSER (-10)

#define OMEMO_INTERNAL_PAYLOAD_SIZE 32
#define OMEMO_INTERNAL_PAYLOAD_MAXPADDEDSIZE 48
#define OMEMO_INTERNAL_HEADER_MAXSIZE (2+33+2*6+2)
#define OMEMO_INTERNAL_FULLMSG_MAXSIZE (1+OMEMO_INTERNAL_HEADER_MAXSIZE+OMEMO_INTERNAL_PAYLOAD_MAXPADDEDSIZE)
#define OMEMO_INTERNAL_ENCRYPTED_MAXSIZE (OMEMO_INTERNAL_FULLMSG_MAXSIZE+8)
#define OMEMO_INTERNAL_PREKEYHEADER_MAXSIZE (1+18+35*2+2)

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

struct omemoState {
  struct omemoKeyPair dhs;
  omemoKey dhr;
  omemoKey rk, cks, ckr;
  uint32_t ns, nr, pn;
};

// [        16        |   16  ]
//  GCM encryption key GCM tag
typedef uint8_t omemoKeyPayload[OMEMO_INTERNAL_PAYLOAD_SIZE];

struct omemoKeyMessage {
  uint8_t p[OMEMO_INTERNAL_PREKEYHEADER_MAXSIZE+OMEMO_INTERNAL_ENCRYPTED_MAXSIZE];
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
  omemoKey pendingek;
  uint32_t pendingpk_id, pendingspk_id;
};

struct omemoBundle {
  omemoCurveSignature spks;
  omemoKey spk, ik; // TODO: use omemoSerializedKey for these?
  omemoKey pk; // Randomly selected prekey
  uint32_t pk_id, spk_id;
};

/*struct omemoCallbacks {
  int (*getrandom)(void *, size_t, void *user);
  int (*loadmessagekey)(struct omemoMessageKey *, void *user);
  int (*storemessagekey)(const struct omemoMessageKey *, void *user);
};*/

/**
 * User supplied function.
 *
 * To pass userdata to this callback, it is recommended to wrap
 * omemoSession within another struct and appending user data fields to
 * the new struct.
 *
 * @param sk has the nr and dh field filled, use them to look up the mk
 * and copy it to st->mk
 * @returns 0 when found or 1 when not found or OMEMO_E*
 */
int omemoLoadMessageKey(struct omemoSession *, struct omemoMessageKey *sk);

/**
 * User supplied function.
 *
 * @see omemoLoadMessageKey()
 */
// TODO: add remaining amount of keys to be stored, so that this
// function can return error if too many.
int omemoStoreMessageKey(struct omemoSession *, const struct omemoMessageKey *);

/**
 * Unimplemented random function.
 *
 * This function should be externally implemented.
 *
 * @param p points to the to-be-filled array
 * @param n is the amount of random bytes which should be generated in p
 * @returns 0 if successful, anything else otherwise
 */
int omemoRandom(void *p, size_t n);

/**
 * Serialize a raw public key into the OMEMO public key format.
 */
void omemoSerializeKey(omemoSerializedKey k, const omemoKey pub);

/**
 * Generate a new store for an OMEMO device.
 */
int omemoSetupStore(struct omemoStore *store);

/**
 * Refill prekeys in store.
 *
 * @returns 0 or OMEMO_ECRYPTO
 */
int omemoRefillPreKeys(struct omemoStore *store);

size_t omemoGetSerializedStoreSize(const struct omemoStore *store);
void omemoSerializeStore(uint8_t *d, const struct omemoStore *store);
int omemoDeserializeStore(const char *p, size_t n, struct omemoStore *store);
size_t omemoGetSerializedSessionSize(const struct omemoSession *session);
void omemoSerializeSession(uint8_t *p, const struct omemoSession *session);

/**
 * @param session must be initialized with omemoSetupSession
 * @return 0 or OMEMO_EPROTOBUF
 */
int omemoDeserializeSession(const char *p, size_t n, struct omemoSession *session);

static inline bool omemoIsSessionInitialized(const struct omemoSession *session) {
  return !!session->fsm;
}

static inline bool omemoIsStoreInitialized(const struct omemoStore *store) {
  return store->isinitialized;
}

/**
 * Initialize OMEMO session from retrieved bundle.
 *
 * The bundle structure must be manually filled with relevant data of a recently retrieved bundle.
 * TODO: @see omemoDeserializeKey()
 */
int omemoInitFromBundle(struct omemoSession *session, const struct omemoStore *store, const struct omemoBundle *bundle);

/**
 * Encrypt message encryption key payload for a specific recipient.
 */
int omemoEncryptKey(struct omemoSession *session, const struct omemoStore *store, struct omemoKeyMessage *msg, const omemoKeyPayload payload);

/**
 * Decrypt message encryption key payload for a specific recipient.
 */
int omemoDecryptKey(struct omemoSession *session, const struct omemoStore *store, omemoKeyPayload payload, bool isprekey, const uint8_t *msg, size_t msgn);

/**
 * Encrypt message which will be stored in the <payload> element.
 *
 * @param payload (out) will contain the encrypted 
 * @param n is the size of the buffer in d and s
 */
int omemoEncryptMessage(uint8_t *d, omemoKeyPayload payload,
                               uint8_t iv[12], const uint8_t *s,
                               size_t n);

/**
 * Decrypt message taken from the <payload> element.
 *
 * @param payload is the decrypted payload of the omemoKeyMessage
 * @param pn is the size of payload, some clients might make the tag larger than 16 bytes
 * @param n is the size of the buffer in d and s
 */
int omemoDecryptMessage(uint8_t *d, const uint8_t *payload, size_t pn, const uint8_t iv[12], const uint8_t *s, size_t n);

#endif
