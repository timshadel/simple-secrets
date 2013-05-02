
var crypto = require('..')
  , node_crypto = require('crypto')
  , expect = require('expect.js')
  , base64url = require('base64url')
  , msg = require('msgpack');

describe('a packet secret maker', function(){

  it('should require a key', function() {
    expect(function(){crypto()}).to.throwException(/key/);
    expect(function(){crypto({key:'a'})}).not.to.throwException();
  });

  it('should make a websafe packet', function() {
    var packet = crypto({key:'a'})({});
    expect(packet).to.be.a('string');
    expect(packet).to.match(/^[a-zA-Z0-9_-]+$/);
  });

  it('should use a simple msgpack array to structure the crypto pieces', function() {
    var packet = msg.unpack(base64url.toBuffer(crypto({key:'a'})({})));
    expect(packet).to.be.an('array');
    expect(packet.length).to.be(3);
    var keyId = packet[0];
    var data = packet[1];
    var mac = packet[2];
    expect(keyId.length).to.be(4);
    expect(data.length).to.be(1);
    expect(mac.length).to.be(32);
  });

  it('should include the keyId', function() {
    var key = '0123456789abcdef0123456789abcdef';
    var packet = msg.unpack(base64url.toBuffer(crypto({key: key})({})));
    var keyId = new Buffer(packet[0]);

    // The keyId is the first 4 bytes of the sha256(keylen || key)
    var hash = node_crypto.createHash('sha256');
    hash.write(String.fromCharCode(32));
    hash.write(key);
    hash.end();

    expect(keyId).to.eql(hash.read().slice(0,4));
  });

  it('should authenticate the encrypted message and the keyId', function() {
    var key = '0123456789abcdef0123456789abcdef';
    var packet = msg.unpack(base64url.toBuffer(crypto({key: key})({})));
    var keyId = new Buffer(packet[0], 'binary');
    var data = new Buffer(packet[1], 'binary');
    var mac = new Buffer(packet[2], 'binary');

    // The HMAC key is derived from the main key + key role
    var hash = node_crypto.createHash('sha256');
    hash.write(key);
    hash.write("simple-crypto/server-mac");
    hash.end();
    var authenticator = node_crypto.createHmac('sha256', hash.read());
    authenticator.write(keyId);
    authenticator.write(data);
    authenticator.end();

    expect(mac).to.eql(authenticator.read());
  });

  it('should encrypt the message', function() {
    var key = '0123456789abcdef0123456789abcdef';
    var packet = msg.unpack(base64url.toBuffer(crypto({key: key})({})));
    var keyId = new Buffer(packet[0], 'binary');
    var data = new Buffer(packet[1], 'binary');
    var mac = new Buffer(packet[2], 'binary');

    // The data key is derived from the main key + key role
    var hash = node_crypto.createHash('sha256');
    hash.write(key);
    hash.write("simple-crypto/server-crypt");
    hash.end();
    var decipher = node_crypto.createDecipher('aes256', hash.read());
    decipher.write(data);
    decipher.end();

    expect({}).to.eql(decipher.read());
  });

});
