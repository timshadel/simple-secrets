
var packet = require('../lib/packet')
  , primitives = require('../lib/primitives')
  , expect = require('expect.js')
  , crypto = require('crypto')
  , sinon = require('sinon');

describe('the Node.js implementation should handle the compatibility standard items', function() {

  var master_key = new Buffer('eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad', 'hex');
  var sender = packet(master_key);

  beforeEach(function() {
    // encryption iv (normally random)
    sinon.stub(crypto, "randomBytes", function() { return new Buffer('7f3333233ce9235860ef902e6d0fcf35', 'hex'); });
    // body nonce (normally random)
    sinon.stub(primitives, "nonce", function() { return new Buffer('83dcf5916c0b5c4bc759e44f9f5c8c50', 'hex'); });
  });

  afterEach(function() {
    crypto.randomBytes.restore();
    primitives.nonce.restore();
  });

  describe('string', function() {
    var string = 'This is the simple-secrets compatibility standard string.';
    var websafe_msgpack1 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0';
    var websafe_msgpack5 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNp54eHe8KRY2JqOo9H8bi3Hnm4G0-r5SNlXXhIW9S99qTxTwibKW7mLkaNMTeZ1ktDwx-4sjCpCnXPIyZe7-l6-o6XjIqazRdhGD6AH5ZS9UFqLpaqIowSUQ9CeiQeFBQ';

    it('create', function() {
      expect(sender.pack(string)).to.eql(websafe_msgpack5);
    });

    it('recover', function() {
      expect(sender.unpack(websafe_msgpack1)).to.eql(string);
      expect(sender.unpack(websafe_msgpack5)).to.eql(string);
    });
  });

  describe('binary', function() {
    var binary = new Buffer(10); binary.fill(0x32);
    var websafe_msgpack1 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yOnGuj4lHrhU_Uv8rMbpjXQJiqd3OMdktrw1asMDXy6jyLrVe9Ea-W09XC90Dgaxlk';
    var websafe_msgpack5 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMVgYX8jn_wUmumA0aJMLlWffSYU0oaJsyJsVjxxF96Ia6mZgAalv5iywbsKORqxtQ';

    it('create', function() {
      expect(sender.pack(binary)).to.eql(websafe_msgpack5);
    });

    it('recover', function() {
      var str1 = sender.unpack(websafe_msgpack1);
      var bin1 = new Buffer(str1, 'utf8');
      expect(bin1).to.eql(binary);
      var bin2 = sender.unpack(websafe_msgpack5);
      expect(bin2).to.eql(binary);
    });
  });

  describe('numbers', function() {
    var integer = 65234;
    var websafe_msgpack1 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yN5I1SH6a75Y_qQlQIclwrVyOk6jJJnMrjeOm6D27_wD0DxwIY9cxSw8boQDgEsLKg';
    // No change to numbers
    var websafe_msgpack5 = websafe_msgpack1;

    it('create', function() {
      expect(sender.pack(integer)).to.eql(websafe_msgpack5);
    });

    it('recover', function() {
      expect(sender.unpack(websafe_msgpack1)).to.eql(integer);
      expect(sender.unpack(websafe_msgpack5)).to.eql(integer);
    });
  });

  describe('nil', function() {
    var nil = null;
    var websafe_msgpack1 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yPYBCYpYMU-4WChi6L1O1GCEApGRhWlg13kVPLTb90cXcEN9vpYgvttgcBJBh6Tjv8';
    // No change to numbers
    var websafe_msgpack5 = websafe_msgpack1;

    it('create', function() {
      expect(sender.pack(nil)).to.eql(websafe_msgpack5);
    });

    it('recover', function() {
      expect(sender.unpack(websafe_msgpack1)).to.eql(nil);
      expect(sender.unpack(websafe_msgpack5)).to.eql(nil);
    });
  });

  describe('array', function() {
    var array = ['This is the simple-secrets compatibility standard array.','This is the simple-secrets compatibility standard array.'];
    var websafe_msgpack1 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMKAFsDUUYwc2fKvPhP_RHYhDOUfJ58li1gJgg9sVeaKx9yC0vFkpxuTmzJP6hZjn6XXlrG6A7-EeNgyzvP547booi2LUi0ALyAzbCaR8abXqnzoNwITRz7TL0J_NkP2gfxbpwUvyBo8ZT0cxGRr9jGnW5F5s6D0jmKZTl209nDJEpXDFRDXCo5y08tmvMNogs7rsZYz74mAap3mrBS-J7W';
    var websafe_msgpack5 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yP5Au9NtEbC-uoWkSPKgnAjODduuH_a2tH-zXaPNdqScWNR8snsQK2OufCVnb2OFk8O7VwgrObvx5gnGgC3pOsmk2Z5CasmOAfzn0B6uEnaBpiMOs74d0d70t07J4MdCRs1aDai9SJqxMpbjz5KJpVmSWqnT3n5KhzEdTLQwCuXQhSA0JKFaAlwQHh5tzq6ToWZZVR34REAGdAo7RMLSSi3';

    it('create', function() {
      expect(sender.pack(array)).to.eql(websafe_msgpack5);
    });

    it('recover', function() {
      expect(sender.unpack(websafe_msgpack1)).to.eql(array);
      expect(sender.unpack(websafe_msgpack5)).to.eql(array);
    });
  });

  describe('map', function() {
    var map = {'compatibility-key': 'This is the simple-secrets compatibility standard map.'};
    var websafe_msgpack1 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXYKrvvhyLbyFTsndgOx5M5yockEUwdSgv6jG_JYpAiU5R37Y7OIZnF3IN2EWtaFSuJko0ajcvoYgDPeLMvjAJdRyBUYIKcvR-g56_p4O7Uef3yJRnfCprG6jUdMyDBai_';
    var websafe_msgpack5 = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXsI6Zwegq5A48uq2i-l13bNQWLY9Ho-lG_s6PzwQhjGz6BnCwAK66YsDBlTqflM-X1mviccZbvUV7K6i2ZPOs8gDUtMIVnu-ByDFopGwZUHjelkUZiLZcRKWXIYSLWyKp';

    it('create', function() {
      expect(sender.pack(map)).to.eql(websafe_msgpack5);
    });

    it('recover', function() {
      expect(sender.unpack(websafe_msgpack1)).to.eql(map);
      expect(sender.unpack(websafe_msgpack5)).to.eql(map);
    });
  });

});
