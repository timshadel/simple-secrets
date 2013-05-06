
# simple-secrets [![Build Status](https://travis-ci.org/timshadel/simple-secrets.png?branch=master)](https://travis-ci.org/timshadel/simple-secrets)

A simple, opinionated library for encrypting small packets of data securely.

## Examples

### Basic

Send:

```js
var secrets = require('simple-secrets');

// Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
var master_key = new Buffer('<64-char hex string (32 bytes, 256 bits)>', 'hex');
var sender = secrets(master_key);
var packet = sender.pack('this is a secret message');
```

Receive:

```js
var secrets = require('simple-secrets');

// Same shared key
var master_key = new Buffer('<shared-key-hex>', 'hex');
var sender = secrets(master_key);
var packet = new Buffer('<read data from somewhere>');
var secret_message = sender.unpack(packet);
```


## Can you add ...

No. Seriously. But we might replace what we have with what you suggest. We want exactly one, well-worn path. If you have improvements, we want them. If you want alternatives to choose from you should probably keep looking.

## License 

MIT.
