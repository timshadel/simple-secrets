
# simple-secrets [![Build Status](https://travis-ci.org/timshadel/simple-secrets.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets)

The Node.js implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages:

* [Node.js](https://github.com/timshadel/simple-secrets)
* [Ruby](https://github.com/timshadel/simple-secrets.rb)
* [Rust](https://github.com/timshadel/simple-secrets.rs)
* [Objective-C](https://github.com/timshadel/SimpleSecrets)
* [Java](https://github.com/timshadel/simple-secrets.java)
* [Erlang](https://github.com/CamShaft/simple_secrets.erl)

## Overview

simple-secrets creates a standard way to turn a JSON-like object into a websafe, encrypted string. We make 4 carefully chosen decisions to create secrets that are as cross-environment compatible as possible.  Here's a visualization of what's happening:

![A diagram of the process used by simple-secrets to pack native objects into encrypted, websafe strings.][packing]

[packing]: ./simple-secrets-packing.png "Overview of simple-secrets packing process"

## Code Examples

### Basic

Send:

```js
var secrets = require('simple-secrets');

// Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
var master_key = new Buffer('<64-char hex string (32 bytes, 256 bits)>', 'hex');
// => <Buffer 71 c8 67 56 23 4b fd 3c 37 ... >

var sender = secrets(master_key);
var packet = sender.pack('this is a secret message');
// => 'OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM'
```

Receive:

```js
var secrets = require('simple-secrets');

// Same shared key
var master_key = new Buffer('<shared-key-hex>', 'hex');
var sender = secrets(master_key);
// read data from somewhere
var packet = 'OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM'
var secret_message = sender.unpack(packet);
// => 'this is a secret message'
```

## Core Decisions

### Serialization - msgpack

[msgpack][msgpack] is a very fast, binary format similar in nature to JSON. It transforms basic native structures into raw bytes compactly, and predictibly. It has implementations in lots of languages, making it highly compatible between environments.

Raw bytes are the breakfast food of champion crypto libs. Small is important byte length greatly impacts both encrypted output length and final encoded string length. This is a foundational decision.

[msgpack]: http://msgpack.org

### Encryption - AES-256-CBC

AES-256 is a good symmetric cipher, providing reasonable security. A random IV is used for each encryption. Our ambitions are for reasonable privacy of content over the course of a year, with the expectation that much of what simple-secrets is used for is valuable for a finite amount of time. AES-256 should far surpass that, but we state our humble expectations knowing that doing crypto is difficult to do right.

### Authentication - HMAC-SHA256

HMAC-SHA256 is a good symmetric authentication primitive. We're aware that Keccak is the new SHA-3 standard for hashing, and has a mode of operation which allows it to produce MACs without the weakness of the length-extension attacks which require older SHA hashes to use the HMAC structure. For now, we're sticking with HMAC-SHA256, but that may change.

### Encoding - base64url

We aim to use secrets produced by this algorithm in several places in HTTP: headers, query string parameters, and message bodies. The base64url encoding allows us to place secrets in all of these places without fear that they'll be incorrectly parsed as indicating the boundary of some key message structure.

### Remnants

We've made other choices, like prepending a 128-bit nonce to the plaintext, including a key identifier as part of the packet, and arranging the binary structure in a specific order for producing and consuming an Encrypt-then-MAC byte array. These choices are important, and are more about the packaging of a message for security than about choosing among algorithm options.

## Discussion

### Crypto Library Implementation

Most of the current implementations use their language bindings to standard OpenSSL libcrypto to do the actual cryptography. Objective-C uses CommonCrypto. In *no case* did we create any cryptographic algorithm implementations. Ours are simply selecting the structure and parameters consistently across a number of implementations to ensure that they are easy to use between systems.

### Don't Trust Us Implicitly

Read the code. Test it. Look for problems, and tell us when you find them. Many eyes make all bugs shallow, and that's especially important in crypto code.

### Decision Updates

We want exactly one, well-worn path. If you have improvements to our choices, our implementations, or our structures, we want them. If you want the option to choose alternatives at runtime, you should probably keep looking.

### License 

MIT.
