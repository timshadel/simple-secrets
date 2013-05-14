
# simple-secrets [![Build Status](https://travis-ci.org/timshadel/simple-secrets.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets)

The Node.js implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages: [Node.js][simple-secrets], [Ruby][simple-secrets.rb], [Objective-C][SimpleSecrets], [Java][simple-secrets.java], [Erlang][simple_secrets.erl].

[simple-secrets]: https://github.com/timshadel/simple-secrets
[simple-secrets.rb]: https://github.com/timshadel/simple-secrets.rb
[SimpleSecrets]: https://github.com/timshadel/SimpleSecrets
[simple-secrets.java]: https://github.com/timshadel/simple-secrets.java
[simple_secrets.erl]: https://github.com/CamShaft/simple_secrets.erl

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
