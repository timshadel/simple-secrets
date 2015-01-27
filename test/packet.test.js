
var packet = require('../lib/packet')
  , expect = require('expect.js')
  , primitives = require('../lib/primitives')
  , helper = require('./helper');

describe('a secret packet', function() {

  it('should accept a 256-bit buffer key', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    expect(sender).not.to.be.empty();
  });

  it('should reject buffer keys that aren\'t 256 bits', function() {
    var master_key = new Buffer(31); master_key.fill(0xbc);
    expect(function() { packet(master_key); }).to.throwException(/256-bit/i);
    master_key = new Buffer(33); master_key.fill(0xbc);
    expect(function() { packet(master_key); }).to.throwException(/256-bit/i);
  });

  it('should accept a 64-char hex key', function() {
    var master_key = 'bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc';
    var sender = packet(master_key);
    expect(sender).not.to.be.empty();
  });

  it('should reject string keys that aren\'t 64 chars', function() {
    var master_key = 'bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb';
    expect(function() { packet(master_key); }).to.throwException(/256-bit/i);
    master_key = 'bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcb';
    expect(function() { packet(master_key); }).to.throwException(/256-bit/i);
    master_key = 'bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbG';
    expect(function() { packet(master_key); }).to.throwException(/256-bit/i);
  });

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
    expect(bin).to.have.length(102);
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

    expect(sender.unpack(p)).to.eql('this is a secret message');
  });

  it('should not be recoverable under a different key', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var p = sender.pack('this is a secret message');
    master_key.fill(0xcb);
    sender = packet(master_key);

    expect.Assertion.prototype.with = function() {
      expect(this.obj).to.be.a('function');
      var fn = this.obj;
      var args = Array.prototype.slice.call(arguments);
      return expect(function() { fn.apply(null, args); });
    }

    expect(sender.unpack(p)).to.not.be.ok();
  });

  it('should recover full objects with primitives', function() {
    var master_key = new Buffer(32); master_key.fill(0xbc);
    var sender = packet(master_key);
    var object = { msg:'this is a secret message', count: 17 };
    var p = sender.pack(object);

    expect(sender.unpack(p)).to.eql(object);
  });

});
