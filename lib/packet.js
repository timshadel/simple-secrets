
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
  this.keyId = primitives.identify(this.master);
}

Packet.prototype.pack = function(data) {
  var nonce, bindata, binplain, keyId, key, hmacKey, cipherdata, binmessage, mac, packet;

  // Turn the data into binary
  nonce = primitives.nonce();
  bindata = primitives.serialize(data);
  binplain = Buffer.concat([nonce, bindata]);

  // Encrypt the binary version of the data
  key = primitives.derive_sender_key(this.master);
  hmacKey = primitives.derive_sender_hmac(this.master);
  cipherdata = primitives.encrypt(bindata, key);

  // Authenticate the (keyId || (iv || ciphertext)); bundle it all together
  binmessage = Buffer.concat([this.keyId, cipherdata]);
  mac = primitives.mac(binmessage, hmacKey);
  packet = Buffer.concat([binmessage, mac]);
  websafe = primitives.stringify(packet);

  // Turn all buffer data into zeros, some of this is sensitive info
  primitives.zero(nonce, bindata, binplain, key, hmacKey, cipherdata, binmessage, mac, packet);
  return websafe;
}

Packet.prototype.unpack = function(websafe) {
  var bindata, pkeyId, key, iv, hmacKey, cipherdata, binmsg, pmac, mac, binpacket;

  binpacket = primitives.binify(websafe);
  binmsg = binpacket.slice(0, -32);
  pmac = binpacket.slice(-32);
  pkeyId = binmsg.slice(0, 6);
  iv = binmsg.slice(6,22);
  cipherdata = binmsg.slice(22);


  keysMatch = primitives.compare(pkeyId, this.keyId);
  if (!keysMatch) {
    data = null;
  } else {
    hmacKey = primitives.derive_sender_hmac(this.master);
    mac = primitives.mac(binmsg, hmacKey);
    valid = primitives.compare(pmac, mac);
    if (!valid) {
      data = null;
    } else {
      key = primitives.derive_sender_key(this.master);
      bindata = primitives.decrypt(cipherdata, key, iv);
      data = primitives.deserialize(bindata);
    }
  }

  primitives.zero(bindata, pkeyId, key, iv, hmacKey, cipherdata, binmsg, pmac, mac,  binpacket);
  return data;
}

