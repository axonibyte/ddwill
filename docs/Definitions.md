# Definitions

There are a few terms used throughout the project... wouldn't it be helpful if
you knew what they meant?

## Payloads

Payloads are the files that are dropped during encryption, some or all of which
must be present for proper decryption. A payload contains some metadata and a
deliverable (the latter of which is either a [canary](#canaries) or a
[shard](#shard)).

Payloads are designed to be readable by at least all minor versions of the same
software. The software should tell you if there's an incompatibility somewhere,
and should give you an idea of what the proper version to use might be.

### Canaries

Canaries are packaged cryptovariables that entirely re-encrypt the
[primary key](#primary-key) associated with the [ciphertext](#ciphertext). All
canaries are required--so if you specify 42 canaries when encrypting the
[plaintext](#plaintext), you're gonna need all 42 canaries to decrypt it.

Canaries are designed so that your [trustees](#trustees) can't execute a hostile
takeover. So stick them in a safety deposit box (if you trust the bank) or design
a canary mechanism for your website that'll reveal the canary if you're not
actively preventing disclosure. Or stick it in your wallet... either way, canaries
are your last line of defense in the event of betrayal.

### Shards

Shards are the files handed to [trustees](#trustees). Each one holds that
trustee's own key and nonce, most (but never all) of the
[ciphertext](#ciphertext), and a set of [fragments](#fragments). No single shard
has all the information needed to reconstruct the [plaintext](#plaintext), even
if brute-forced... it's designed such that you'll always need at least two shards
to reconstruct the [ciphertext](#ciphertext) and [primary key](#primary-key)
before the system can finish decrypting things.

#### Fragments

A fragment is one entry inside a shard, and there is one for every possible
[quorum](#quorum) the shard's trustee could be part of. It holds the encrypted
[primary key](#primary-key), sealed once more with the XOR of the keys of the
_other_ trustees in that quorum, along with the list of who those trustees are. A fragment can only be
opened once every one of those trustees has handed in their shard.

Shards are designed to be distributed to various [trustees](#trustees). A
[quorum](#quorum) of them need to hand in their keys (along with any
[canaries](#canaries)) in order to recover the [plaintext](#plaintext).

### Recovery codes

A short code (like `3-7Q4M-XJ9K-2C8D-F0ZV-5RWT`) generated for each
[shard](#shards) at encryption time and shown exactly once. The shard's secrets
are sealed under a key derived from it (Argon2id), so the shard file and the
code are two halves of one share: deliver them separately, and losing one to an
attacker loses nothing. The leading number says which shard the code belongs to.

## Trustees

These are humans that you trust to hold onto one of your [shards](#shards). They
should be your closest confidantes. You need to have at least two (2) trustees--
otherwise, you might as well use some other standard encryption software.

### Quorum

This is the minimum number of trustees required to recover your
[plaintext](#plaintext). You need to have at least a quorum of two (2)...
otherwise, you might as well use some other standard encryption software.

## Plaintext

Strictly speaking, plaintext is the thing to be encrypted, and the product of the
decryption process if you do everything correctly.

### Ciphertext

Ciphertext is the encrypted plaintext, which is broken up and vaguely distributed
throughout the [shards](#shards).
