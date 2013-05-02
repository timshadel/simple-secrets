
/**
 * Module dependencies.
 */

var primitives = require('./primitives');


/**
 * Expose packet as the module.
 */

exports = module.exports = function(key) {
  return new Packet(key);
}

function Packet(key) {
  this.master = key;
}

Packet.prototype.pack = function(data) {
  var nonce, bindata, keyId, key, hmacKey, cipherdata, binmessage, mac, packet;

  // Turn the data into binary
  nonce = primitives.nonce();
  bindata = primitives.serialize([nonce, data]);

  // Encrypt the binary version of the data
  keyId = primitives.identify(this.master);
  key = primitives.derive(this.master, 'simple-crypto/cipher-key');
  hmacKey = primitives.derive(this.master, 'simple-crypto/hmac-key');
  cipherdata = primitives.encrypt(bindata, key);

  // Authenticate the keyId and ciphertext; bundle it all together
  binmessage = primitives.serialize([keyId, cipherdata]);
  mac = primitives.mac(binmessage, hmacKey);
  packet = primitives.serialize([keyId, cipherdata, mac]);
  websafe = primitives.stringify(packet);

  // Turn all buffer data into zeros, some of this is sensitive info
  primitives.zero(nonce, bindata, keyId, key, hmacKey, cipherdata, binmessage, mac, packet);
  return packet;
}

Packet.prototype.unpack = function(websafe) {
  var nonce, bindata, keyId, key, hmacKey, cipherdata, binmessage, mac, packet;

  binpacket = primitives.binify(websafe);
  packet = primitives.deserialize(binpacket);
  packet_keyId = packet[0];
  cipherdata = packet[1];
  packet_mac = packet[2];

  keyId = primitives.identify(this.master);
  keysMatch = primitives.compare(packet_keyId, keyId);
  // don't exit here

  key = primitives.derive(this.master, 'simple-crypto/cipher-key');
  hmacKey = primitives.derive(this.master, 'simple-crypto/hmac-key');

  binmessage = primitives.serialize([keyId, cipherdata]);
  mac = primitives.mac(binmessage, hmacKey);
  valid = primitives.compare(packet_mac, mac);
  // exit here

  bindata = primitives.decrypt(cipherdata, key);
  original = primitives.deserialize(bindata);
  nonce = original[0];
  data = original[1];

  primitives.zero(bindata, keyId, key, hmacKey, cipherdata, binmessage, mac);
  return data;
}

