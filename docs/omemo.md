Draft

## Resource usage

### Heap memory

The heap memory that's allocated by omemo* functions are all deallocated
before they return. This makes heap memory leaks impossible (except if
that's done in omemoRandom).

All heap allocations done in omemo* functions are done by MbedTLS, these
allocation sizes never exceed a certain amount, even when changing
omemo* function parameters. MbedTLS allows you to use static memory for
allocation, which could be taken advantage of.

### CPU

All functions have constant time complexity, with some exceptions.

A maliciously large protobuf in omemoDecryptKey could be entirely read,
however this shouldn't take too many resources.

omemoSetupStore is very expensive on microcontrollers, because it
generates a lot of prekeys. It is advised you generate these before a
microcontroller starts up (look at examples/im.c). And always call
omemoRefillPreKeys after one is used.

A malicious keymessage could want you to skip millions of prekeys, which
would take a lot of resources. It is expected the user of the library
will decide whether they want to deal with that, that is, stop calling
omemoSkipMessageKey after n times. The OMEMO spec recommends MAX\_SKIP
to be around 1000.

## Storage

The skipped message keys should be stored after calling
omemoSkipMessageKey.

## Usage

```c
r = omemoParseKeyMessage(..., out msgdecoder);
// Handle r

// All the following code is for storing/loading skipped message keys.
// When that functionality is not desired, you can omit it without
// causing issues down the line (however, you might miss old messages).

BeginTransaction();

if (LoadMessageKey(..., msgdecoder) == SUCCESS) {
    omemoSupplyMessageKey(...);
    // Remove within transaction. If any following omemo call fails
    // key should not be removed.
    RemoveMessageKey();
}

while (!(r = omemoSkipMessageKey(...))) {
    // Again, in transaction...
    Store(...);
}
// Handle r if r < 0

r = omemoDecryptKeyMessage(...);
// Handle r

// Everything is fine, we can now update the database.
CommitTransaction();
```

