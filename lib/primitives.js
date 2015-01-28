
/**
 * Module dependencies.
 */

var crypto = require('crypto')
  , base64url = require('base64url')
  , msg = require('msgpack5')();


/**
 * Expose primitives as the module.
 *
 * WARNING: Using any of these primitives in isolation could be Bad. Take cautious.
 */

var primitives = module.exports = {};


/**
 * Provide 16 securely random bytes.
 *
 * @return {Buffer} 16 random bytes
 * @api public
 */

primitives.nonce = function() {
  return crypto.randomBytes(16);
}


/**
 * Generate an encryption or hmac key from the master key and role.
 * Uses SHA256(key || role).
 *
 * @param {Buffer} master_key  the 256-bit master key of this secure channel
 * @param {String} role  in what part of the protocol will this key be used
 * @return {Buffer} 256-bit derived key
 * @see [TODO: link or citation]
 * @api public
 */

function derive(master_key, role) {
  assertBuffer(master_key);
  assert256BitBuffer(master_key);
  var hash = crypto.createHash('sha256');
  hash.write(master_key);
  hash.write(new Buffer(role,'ascii'));
  hash.end();
  return hash.read();
}


/**
 * Generate the authentication key for messages originating from
 * the channel's Sender side.
 *
 * Uses the ASCII string 'simple-crypto/sender-hmac-key' as the role.
 *
 * @param {Buffer} master_key  the 256-bit master key of this secure channel
 * @return {Buffer} 256-bit sender hmac key
 * @api public
 */

primitives.derive_sender_hmac = function(master_key) {
  return derive(master_key, 'simple-crypto/sender-hmac-key');
}


/**
 * Generate the encryption key for messages originating from the
 * channel's Sender side.
 *
 * Uses the ASCII string 'simple-crypto/sender-cipher-key' as the role.
 *
 * @param {Buffer} master_key  the 256-bit master key of this secure channel
 * @return {Buffer} 256-bit sender encryption key
 * @api public
 */

primitives.derive_sender_key = function(master_key) {
  return derive(master_key, 'simple-crypto/sender-cipher-key');
}


/**
 * Generate the authentication key for messages originating from
 * the channel's Receiver side.
 *
 * Uses the ASCII string 'simple-crypto/receiver-hmac-key' as the role.
 *
 * @param {Buffer} master_key  the 256-bit master key of this secure channel
 * @return {Buffer} 256-bit receiver hmac key
 * @api public
 */

primitives.derive_receiver_hmac = function(master_key) {
  return derive(master_key, 'simple-crypto/receiver-hmac-key');
}


/**
 * Generate the encryption key for messages originating from the
 * channel's Receiver side.
 *
 * Uses the ASCII string 'simple-crypto/receiver-cipher-key' as the role.
 *
 * @param {Buffer} master_key  the 256-bit master key of this secure channel
 * @return {Buffer} receiver  256-bit encryption key
 * @api public
 */

primitives.derive_receiver_key = function(master_key) {
  return derive(master_key, 'simple-crypto/receiver-cipher-key');
}


/**
 * Encrypt buffer with the given key.
 *
 * Uses AES256 with a random 128-bit initialization vector.
 *
 * @param {Buffer} buffer  plaintext
 * @param {Buffer} key  256-bit encryption key
 * @return {Array} [128-bit IV, ciphertext]
 * @api public
 */

primitives.encrypt = function(buffer, key) {
  assertBuffer(buffer, key);
  assert256BitBuffer(key);
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv('aes256', key, iv);
  cipher.write(buffer);
  cipher.end();
  return Buffer.concat([iv, cipher.read()]);
}


/**
 * Decrypt buffer with the given key and initialization vector.
 *
 * Uses AES256.
 *
 * @param {Buffer} buffer  ciphertext
 * @param {Buffer} key  256-bit encryption key
 * @param {Buffer} iv  128-bit initialization vector
 * @return {Buffer} plaintext
 * @api public
 */

primitives.decrypt = function(buffer, key, iv) {
  assertBuffer(buffer, key, iv);
  assert256BitBuffer(key);
  assert128BitBuffer(iv);
  var decipher = crypto.createDecipheriv('aes256', key, iv);
  decipher.write(buffer);
  decipher.end();
  return decipher.read();
}


/**
 * Create a short identifier for potentially sensitive data.
 *
 * @param {Buffer} buffer the data to identify
 * @return {Buffer} 6-byte identifier
 * @api public
 */

primitives.identify = function(buffer) {
  assertBuffer(buffer);
  var len = new Buffer(1);
  len.writeUInt8(buffer.length, 0);
  var hash = crypto.createHash('sha256');
  hash.write(len);
  hash.write(buffer);
  hash.end();
  return hash.read().slice(0,6);
}


/**
 * Create a message authentication code for the given data.
 *
 * Uses HMAC-SHA256.
 *
 * @param {Buffer} buffer data to authenticate
 * @param {Buffer} hmacKey the authentication key
 * @return {Buffer} 32-byte MAC
 * @api public
 */

primitives.mac = function(buffer, hmacKey) {
  assertBuffer(buffer, hmacKey);
  assert256BitBuffer(hmacKey);
  var hmac = crypto.createHmac('sha256', hmacKey);
  hmac.write(buffer);
  hmac.end();
  return hmac.read();
}


/**
 * Use a constant-time comparison algorithm to reduce
 * side-channel attacks.
 *
 * Short-circuits only when the two buffers aren't the same length.
 *
 * @param {Buffer} a
 * @param {Buffer} b
 * @return {Boolean} true if both buffer contents match
 * @api public
 */

primitives.compare = function(a, b) {
  assertBuffer(a, b);

  // things must be the same length to compare them.
  if (a.length != b.length) return false;

  // constant-time compare
  //   hat-tip to https://github.com/freewil/scmp for |=
  var same = 0;
  for (var i = 0; i < a.length; i++) {
    same |= a[i] ^ b[i];
  }
  return same === 0;
}


/**
 * Turn a websafe string back into a binary buffer.
 *
 * Uses base64url encoding.
 *
 * @param {String} websafe string
 * @return {Buffer} the binary version of this string
 * @api public
 */

primitives.binify = function(string) {
  if (typeof string !== 'string' || !string.match(/^[a-zA-Z0-9_\-]+$/)) {
    throw new Error('base64url string required.');
  }
  return base64url.toBuffer(string);
}


/**
 * Turn a binary buffer into a websafe string.
 *
 * Uses base64url encoding.
 *
 * @param {Buffer} binary data which needs to be websafe
 * @return {String} the websafe string
 * @api public
 */

primitives.stringify = function(buffer) {
  assertBuffer(buffer);
  return base64url(buffer);
}


/**
 * Turn a JavaScript object into a binary representation
 * suitable for use in crypto functions. This object will
 * possibly be deserialized in a different programming
 * environment—it should be JSON-like in structure.
 *
 * Uses MsgPack data serialization.
 *
 * @param {Object} object Any JavaScript object without cycles
 * @return {Buffer} The binary version of this object
 * @api public
 */

primitives.serialize = function(object) {
  return msg.encode(object);
}


/**
 * Turn a binary representation into a JavaScript object
 * suitable for use in application logic. This object
 * possibly originated in a different programming
 * environment—it should be JSON-like in structure.
 *
 * Uses MsgPack data serialization.
 *
 * @param {Object} any JavaScript object without cycles
 * @return {Buffer} the binary version of this object
 * @api public
 */

primitives.deserialize = function(buffer) {
  assertBuffer(buffer);
  return copyBuffer(msg.decode(buffer));
}


/**
 * Overwrite the contents of the buffer with zeroes.
 * This is critical for removing sensitive data from memory.
 *
 * @param {Buffer} buffer The buffer to clean out.
 * @api public
 */

primitives.zero = function() {
  assertBuffer.apply(this, arguments);
  for (var i = 0; i < arguments.length; i++) {
    var buf = arguments[i];
    for (var j = 0; j < buf.length; j++) {
      buf.writeUInt8(0, j);
    }
  }
}


/**
 * Check that every argument is a Buffer
 *
 * @param {Buffer} binary data which needs to be websafe
 * @throws {Error} on the first argument that is not a Buffer.
 * @api public
 */

function assertBuffer() {
  for (var i = 0; i < arguments.length; i++) {
    if (!Buffer.isBuffer(arguments[i])) {
      throw new Error('Buffer object required. Argument ' + i + ' is not a Buffer.');
    }
  }
}

function copyBuffer(buffer) {
  if (Buffer.isBuffer(buffer)) {
    var copy = new Buffer(buffer.length);
    buffer.copy(copy);
    return copy;
  } else {
    return buffer;
  }
}

function assert256BitBuffer(buffer) {
  if (buffer.length != 32) {
    throw new Error('256-bit buffer required.');
  }
}

function assert128BitBuffer(buffer) {
  if (buffer.length != 16) {
    throw new Error('128-bit buffer required.');
  }
}
