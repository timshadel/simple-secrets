
/**
 * Module dependencies.
 */

var crypto = require('crypto')
  , base64url = require('base64url')
  , msg = require('msgpack');


/**
 * Expose primitives as the module.
 */

var primitives = module.exports = {};


/**
 * Provide 16 securely random bytes.
 */

primitives.nonce = function() {
  return crypto.randomBytes(16);
}


/**
 * Generate an encryption or hmac key from the master key and role.
 *
 * @see [TODO: link or citation]
 * @api public
 */

function derive(master_key, role) {
  var hash = crypto.createHash('sha256');
  hash.write(master_key);
  hash.write(new Buffer(role,'ascii'));
  hash.end();
  return hash.read();
}

primitives.derive_sender_hmac = function(master_key) {
  return derive(master_key, 'simple-crypto/sender-hmac-key');
}

primitives.derive_sender_key = function(master_key) {
  return derive(master_key, 'simple-crypto/sender-cipher-key');
}

primitives.derive_receiver_hmac = function(master_key) {
  return derive(master_key, 'simple-crypto/receiver-hmac-key');
}

primitives.derive_receiver_key = function(master_key) {
  return derive(master_key, 'simple-crypto/receiver-cipher-key');
}


primitives.encrypt = function(data, key) {
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv('aes256', key, iv);
  cipher.write(data);
  cipher.end();
  return [iv, cipher.read()];
}

primitives.decrypt = function(ciphered, key, iv) {
  var decipher = crypto.createDecipheriv('aes256', key, iv);
  decipher.write(ciphered);
  decipher.end();
  return decipher.read();
}


primitives.identify = function(buffer) {
  var hash = crypto.createHash('sha256');
  hash.write(buffer.length);
  hash.write(buffer);
  hash.end();
  return hash.read().slice(0,6);
}

primitives.mac = function(data, hmacKey) {
  // TODO: Start here
}

primitives.compare = function() {

}


primitives.binify = function() {

}

primitives.stringify = function() {

}

primitives.serialize = function() {

}

primitives.deserialize = function() {

}


primitives.zero = function() {

}

