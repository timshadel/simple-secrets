
# simple-secrets [![Build Status](https://travis-ci.org/timshadel/simple-secrets.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets)

The Node.js implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages: [Node.js][simple-secrets], [Ruby][simple-secrets.rb], [Objective-C][SimpleSecrets], [Java][simple-secrets.java], [Erlang][simple_secrets.erl].

[simple-secrets]: https://github.com/timshadel/simple-secrets
[simple-secrets.rb]: https://github.com/timshadel/simple-secrets.rb
[SimpleSecrets]: https://github.com/timshadel/SimpleSecrets
[simple-secrets.java]: https://github.com/timshadel/simple-secrets.java
[simple_secrets.erl]: https://github.com/CamShaft/simple_secrets.erl

## Overview

simple-secrets creates a standard way to turn a JSON-like object into a websafe, encrypted string. We make a number of very carefully chosen decisions to make it as cross-environment compatible as possible. Here's the basic idea

     <Object in Memory>     - Start with an object in the target language
            |
            V
        (msgpack)           - msgpack is a very fast, binary format similar in nature to JSON.
            |                 It transforms data into raw bytes compactly, and predictibly.
            V
    [    raw bytes     ]    - Raw bytes are the breakfast of champion crypto libs.
            |
            V
         (nonce)            - A 128-bit nonce is prepended to the raw bytes, since those often have
            |                 predictable structure.
            V
        (AES-256)           - AES-256 is a decent symmetric cipher, providing reasonable security.
            |                 A random IV is used for each encryption.
            V
      (HMAC-SHA256)         - A symmetric signature that aligns in size and bits of security with
            |                 AES-256 chosen above. The key identifier, IV, and ciphertext are MAC'd.
            V
    [   binary packet  ]    - It's more than just encrypted bytes; there's a specific structure for
            |                 security. It's got the IV and the HMAC, plus an identifier of the key.
            V
    [ base64url string ]    - A string of text that's suitable for use anywhere in HTTP or URIs.
                              This is awesome since we want to use this for OAuth tokens and more.

## Examples

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


## Can you add ...

No. Seriously. But we might replace what we have with what you suggest. We want exactly one, well-worn path. If you have improvements, we want them. If you want alternatives to choose from you should probably keep looking.

## License 

MIT.
