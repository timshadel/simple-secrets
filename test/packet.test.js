
var packet = require('../lib/packet')
  , expect = require('expect.js')
  , primitives = require('../lib/primitives');

describe('a secret packet', function() {

  it('should be a websafe string', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var p = sender.pack('this is a secret message');

    expect(p).to.be.a('string');
    expect(p).to.match(/^[a-zA-Z0-9_\-]+$/);
  });

  it('should be an encoded buffer', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var p = sender.pack('this is a secret message');
    var bin = primitives.binify(p);

    expect(bin).to.be.a(Buffer);
    expect(bin).to.have.length(86);
  });

  it('should have a mac which authenticates the message', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var p = sender.pack('this is a secret message');
    var bin = primitives.binify(p);
    var binmsg = bin.slice(0, -32);
    var mac = bin.slice(-32);
    var keyId = binmsg.slice(0, 6);
    var iv = binmsg.slice(6,22);
    var ciphertext = binmsg.slice(22);

    var hmacKey = primitives.derive_sender_hmac(master_key);

    expect(mac).to.be.a(Buffer);
    expect(mac).to.have.length(32);
    expect(keyId).to.eql(primitives.identify(master_key));
    expect(mac).to.eql(primitives.mac(binmsg, hmacKey));
  });

  it('should have a recoverable ciphertext', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var p = sender.pack('this is a secret message');
    var bin = primitives.binify(p);
    var binmsg = bin.slice(0, -32);
    var mac = bin.slice(-32);
    var keyId = binmsg.slice(0, 6);
    var iv = binmsg.slice(6,22);
    var ciphertext = binmsg.slice(22);

    var key = primitives.derive_sender_key(master_key);
    var plainpacket = primitives.decrypt(ciphertext, key, iv);
    var original = primitives.deserialize(plainpacket);

    expect(iv).to.be.a(Buffer);
    expect(iv).to.have.length(16);
    expect(keyId).to.eql(primitives.identify(master_key));
    expect(original).to.eql('this is a secret message');
  });


  it('should not be recoverable without the key', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var p = sender.pack('this is a secret message');

    expect.Assertion.prototype.with = function() {
      expect(this.obj).to.be.a('function');
      var fn = this.obj;
      var args = Array.prototype.slice.call(arguments);
      return expect(function() { fn.apply(null, args); });
    }

    // Now we have a different key
    master_key.fill(0xcb);

    var bin = primitives.binify(p);
    var iv = bin.slice(6,22);
    var ciphertext = bin.slice(22, -32);

    var key = primitives.derive_sender_key(master_key);
    expect(primitives.decrypt).with(ciphertext, key, iv).to.throwException(/bad decrypt/);
  });

  it('should be recoverable', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var p = sender.pack('this is a secret message');

    expect(sender.unpack(p)).to.eql('this is a secret message');
  });

});
