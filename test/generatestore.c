#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

#include "omemo.h"

int omemoRandom(void *d, size_t n) { return getrandom(d, n, 0) != n; }

int main() {
  struct omemoStore store;
  assert(!omemoSetupStore(&store));
  size_t n = omemoGetSerializedStoreSize(&store);
  char *buf = malloc(n);
  assert(buf);
  omemoSerializeStore(buf, &store);
  fwrite(buf, n, 1, stdout);
}
