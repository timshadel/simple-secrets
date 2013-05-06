
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

function buildBody(data) {
  var nonce = primitives.nonce();
  var bindata = primitives.serialize(data);
  var body = Buffer.concat([nonce, bindata]);

  primitives.zero(nonce, bindata);
  return body;
}

function bodyToData(body) {
  var nonce = body.slice(0, 16);
  var bindata = body.slice(16);
  var data = primitives.deserialize(bindata);

  primitives.zero(nonce, bindata);
  return data;
}

function encryptBody(body, master) {
  var key = primitives.derive_sender_key(master);
  var cipherdata = primitives.encrypt(body, key);

  primitives.zero(key);
  return cipherdata;
}

function decryptBody(cipherdata, master) {
  var key = primitives.derive_sender_key(master);
  var iv = cipherdata.slice(0, 16);
  var encrypted = cipherdata.slice(16);
  var body = primitives.decrypt(encrypted, key, iv);

  primitives.zero(key, iv, encrypted);
  return body;
}

function authenticate(data, master, keyId) {
  // Authenticate the (keyId || iv || ciphertext); bundle it all together
  var hmacKey = primitives.derive_sender_hmac(master);
  var auth = Buffer.concat([keyId, data]);
  var mac = primitives.mac(auth, hmacKey);
  var packet = Buffer.concat([keyId, data, mac]);

  primitives.zero(hmacKey, mac);
  return packet;
}

function verify(packet, master, keyId) {
  // Authenticate the (keyId || iv || ciphertext); bundle it all together
  var packet_keyId = packet.slice(0, 6);

  if (!primitives.compare(packet_keyId, keyId)) {
    return null;
  }

  var data = packet.slice(0, -32);
  var packet_mac = packet.slice(-32);
  var hmacKey = primitives.derive_sender_hmac(master);
  var mac = primitives.mac(data, hmacKey);
  var valid = primitives.compare(packet_mac, mac);
  var data = valid ? packet.slice(6, -32) : null;

  primitives.zero(hmacKey, mac);
  return data;
}

Packet.prototype.pack = function(data) {
  var body = buildBody(data);
  var encrypted = encryptBody(body, this.master);
  var packet = authenticate(encrypted, this.master, this.keyId);
  var websafe = primitives.stringify(packet);

  primitives.zero(body, encrypted, packet);
  return websafe;
}

Packet.prototype.unpack = function(websafe) {
  var packet = primitives.binify(websafe);
  var cipherdata = verify(packet, this.master, this.keyId);
  var body = null;
  var data = null;

  if (cipherdata) {
    body = decryptBody(cipherdata, this.master);
    data = bodyToData(body);
    primitives.zero(body, cipherdata);
  }

  primitives.zero(packet);
  return data;
}

