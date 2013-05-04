
var primitives = require('../lib/primitives')
  , expect = require('expect.js');

describe('primitive crypto functions', function() {

  describe('nonce()', function() {
    it('should return 16 random bytes', function() {
      expect(primitives.nonce()).to.have.length(16);
      expect(primitives.nonce()).not.equal(primitives.nonce());
    });
  });

  describe('all crypto functions', function() {
    it('should require Buffers as input', function() {
      var str = ''
      var buf = new Buffer(10); buf.fill(0x32);

      expect.Assertion.prototype.with = function() {
        expect(this.obj).to.be.a('function');
        var fn = this.obj;
        var args = Array.prototype.slice.call(arguments);
        return expect(function() { fn.apply(null, args); });
      }

      expect.Assertion.prototype.complain = function() {
        return this.throwException(/not a buffer/i);
      }

      function check() {
        var fns = Array.prototype.slice.call(arguments);
        fns.forEach(function(fn) {
          expect(fn).with(str).to.complain();
          expect(fn).with(buf).not.to.complain();
        });
      }

      check(
        primitives.derive_sender_hmac,
        primitives.derive_sender_key,
        primitives.derive_receiver_hmac,
        primitives.derive_receiver_key
      );

      expect(primitives.encrypt).with(str, str).to.complain();
      expect(primitives.encrypt).with(buf, str).to.complain();
      expect(primitives.encrypt).with(buf, buf).not.to.complain();

      expect(primitives.decrypt).with(str, str, str).to.complain();
      expect(primitives.decrypt).with(buf, str, str).to.complain();
      expect(primitives.decrypt).with(buf, buf, str).to.complain();
      expect(primitives.decrypt).with(buf, buf, buf).not.to.complain();

      expect(primitives.mac).with(str, str).to.complain();
      expect(primitives.mac).with(buf, str).to.complain();
      expect(primitives.mac).with(buf, buf).not.to.complain();
    });

    it('should require a 256-bit key', function() {
      var short = new Buffer(31); short.fill(0x33);
      var exact = new Buffer(32); exact.fill(0x33);
      var long = new Buffer(33); long.fill(0x33);

      function check(fns) {
        for (var i = 0; i < fns.length; i++) {
          var fn = fns[i];
          expect(function(){ fn(short); }).to.throwException(/256-bit/i);
          expect(fn(exact)).to.be.a(Buffer);
          expect(function(){ fn(long); }).to.throwException(/256-bit/i);
        }
      }

      check([
        primitives.derive_sender_hmac,
        primitives.derive_sender_key,
        primitives.derive_receiver_hmac,
        primitives.derive_receiver_key
      ]);
    });
  });

  describe('most utility functions', function() {
    it('should require Buffers as input', function() {
      var str = ''
      var buf = new Buffer(10); buf.fill(0x23);

      expect(function(){ primitives.identify(str); }).to.throwException(/not a buffer/i);
      expect(function(){ primitives.identify(buf); }).not.to.throwException();
      primitives.identify(buf);

      expect(function(){ primitives.compare(str, str); }).to.throwException(/not a buffer/i);
      expect(function(){ primitives.compare(buf, str); }).to.throwException(/not a buffer/i);
      expect(function(){ primitives.compare(buf, buf); }).not.to.throwException();

      expect(function(){ primitives.stringify(str); }).to.throwException(/not a buffer/i);
      expect(function(){ primitives.stringify(buf); }).not.to.throwException();
    });
  });

  describe('derive_sender_hmac()', function() {
    it('should derive a 256-bit hmac key from a 256-bit master key', function() {
      var master_key = new Buffer(32); master_key.fill(0xbc);

      var hmac_key = primitives.derive_sender_hmac(master_key);
      expect(hmac_key).to.have.length(32);
      expect(hmac_key).to.eql(new Buffer('1e2e2725f135463f05c268ffd1c1687dbc9dd7da65405697471052236b3b3088', 'hex'));
    });
  });

  describe('derive_sender_key()', function() {
    it('should derive a 256-bit encryption key from a 256-bit master key', function() {
      var master_key = new Buffer(32); master_key.fill(0xbc);

      var hmac_key = primitives.derive_sender_key(master_key);
      expect(hmac_key).to.have.length(32);
      expect(hmac_key).to.eql(new Buffer('327b5f32d7ff0beeb0a7224166186e5f1fc2ba681092214a25b1465d1f17d837', 'hex'));
    });
  });

  describe('derive_receiver_hmac()', function() {
    it('should derive a 256-bit hmac key from a 256-bit master key', function() {
      var master_key = new Buffer(32); master_key.fill(0xbc);

      var hmac_key = primitives.derive_receiver_hmac(master_key);
      expect(hmac_key).to.have.length(32);
      expect(hmac_key).to.eql(new Buffer('375f52dff2a263f2d0e0df11d252d25ba18b2f9abae1f0cbf299bab8d8c4904d', 'hex'));
    });
  });

  describe('derive_receiver_key()', function() {
    it('should derive a 256-bit encryption key from a 256-bit master key', function() {
      var master_key = new Buffer(32); master_key.fill(0xbc);

      var hmac_key = primitives.derive_receiver_key(master_key);
      expect(hmac_key).to.have.length(32);
      expect(hmac_key).to.eql(new Buffer('c7e2a9660369f243aed71b0de0c49ee69719d20261778fdf39991a456566ef22', 'hex'));
    });
  });

  describe.skip('encrypt()', function() {
  });

  describe.skip('decrypt()', function() {
  });

  describe.skip('identify()', function() {
  });

  describe.skip('mac()', function() {
  });

  describe.skip('compare()', function() {
  });

  describe.skip('binify()', function() {
  });

  describe.skip('stringify()', function() {
  });

  describe.skip('serialize()', function() {
  });

  describe.skip('deserialize()', function() {
  });

  describe('zero()', function() {

    it('should require a Buffer', function() {
      expect(function(){ primitives.zero({}); }).to.throwException(/not a buffer/i);
    });

    it('should overwrite all buffer contents with zeros', function() {
      var b = new Buffer([74, 68, 69, 73, 20, 69, 73, 20, 73, 0x6f, 0x6d, 65]);
      var z = new Buffer([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

      // different contents
      expect(b).not.to.eql(z);

      primitives.zero(b);

      // different identity, same contents
      expect(b).not.to.equal(z);
      expect(b).to.eql(z);
    });

  });

});