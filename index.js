
/**
 * Module dependencies.
 */

var internal_crypto = require('crypto')
  , base64url = require('base64url')
  , msg = require('msgpack');


/**
 * Expose crypto as the module.
 */
exports = module.exports = crypto;


var role = {
  server: {
    crypt: "simple-crypto/server-crypt",
    mac:   "simple-crypto/server-mac"
  },
  client: {
    crypt: "simple-crypto/client-crypt",
    mac:   "simple-crypto/client-mac"
  }
}


/**
 *
 */

function crypto(config) {
  config = config || {};
  if (!config.key) throw new Error('No crypto key!');

  var context = {
    key: config.key,
    keyId: hash('createHash')(config.key.length, config.key).slice(0,4)
  }

  function box(object) {
    // See http://nodejs.org/api/buffer.html#buffer_buf_tojson
    var k = context.keyId;
    var keyId = [ k[0], k[1], k[2], k[3] ];
    var data = msg.pack(object);
    var cipher = encrypt(data, makeKey(context.key, role.server.crypt))
    var mac = authenticate(keyId, data, makeKey(context.key, role.server.mac));
    return base64url(msg.pack([keyId, data.toString('binary'), mac.toString('binary')]));
  }

  box.unbox = function unbox(packet) {
    return packet;
  }

  return box;
}

function hash(fn, key) {
  return function() {
    var args = Array.prototype.slice.call(arguments)
      , impl = key ? internal_crypto[fn]('sha256', key) : internal_crypto[fn]('sha256');

    args.forEach(function(item) {
      var t = coerce(item);
      impl.write(t);
    }); impl.end();

    var h = impl.read();
    return h;
  }
}

function makeKey(master, role) {
  return hash('createHash')(master, role);
}

function authenticate() {
  var args = Array.prototype.slice.call(arguments)
    , key = args.pop();

  return hash('createHmac', key).apply(null, args);
}

function coerce(object) {
  if (typeof object === 'number' && object < 128) {
    return String.fromCharCode(object);
  }
  if (Array.isArray(object)) return new Buffer(object);

  return object;
}

function trunc(buf) {
  return [buf[0], buf[1], buf[2], buf[3]];
}