
# simple-crypto [![Build Status](https://travis-ci.org/timshadel/simple-crypto.png?branch=master)](https://travis-ci.org/timshadel/simple-crypto)

A simple, opinionated library for encrypting small packets of data securely.

## Examples

### Basic

```js
var crypto = require('simple-crypto')(config);

var packet = crypto(data);
```

The __`DEBUG`__ environment variable used to enable logging. Give it space- or comma-separated names.

```console
$ DEBUG=mything node myapp
doing something useful
doing something useful
doing something useful
```

## Can you add ...

No. Seriously. But we might replace what we have with what you suggest. We want exactly one, well-worn path. If you have improvements, we want them. If you want alternatives to choose from you should probably keep looking.

## License 

MIT.
