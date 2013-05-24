
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
    var websafe = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0';

    it('create', function() {
      expect(sender.pack(string)).to.eql(websafe);
    });

    it('recover', function() {
      expect(sender.unpack(websafe)).to.eql(string);
    });
  });

  describe('numbers', function() {
    var int = 65234;
    var websafe = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yN5I1SH6a75Y_qQlQIclwrVyOk6jJJnMrjeOm6D27_wD0DxwIY9cxSw8boQDgEsLKg';

    it('create', function() {
      expect(sender.pack(int)).to.eql(websafe);
    });

    it('recover', function() {
      expect(sender.unpack(websafe)).to.eql(int);
    });
  });

  describe('nil', function() {
    var nil = null;
    var websafe = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yPYBCYpYMU-4WChi6L1O1GCEApGRhWlg13kVPLTb90cXcEN9vpYgvttgcBJBh6Tjv8';

    it('create', function() {
      expect(sender.pack(nil)).to.eql(websafe);
    });

    it('recover', function() {
      expect(sender.unpack(websafe)).to.eql(nil);
    });
  });

  describe('array', function() {
    var array = ['This is the simple-secrets compatibility standard array.','This is the simple-secrets compatibility standard array.'];
    var websafe = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMKAFsDUUYwc2fKvPhP_RHYhDOUfJ58li1gJgg9sVeaKx9yC0vFkpxuTmzJP6hZjn6XXlrG6A7-EeNgyzvP547booi2LUi0ALyAzbCaR8abXqnzoNwITRz7TL0J_NkP2gfxbpwUvyBo8ZT0cxGRr9jGnW5F5s6D0jmKZTl209nDJEpXDFRDXCo5y08tmvMNogs7rsZYz74mAap3mrBS-J7W';

    it('create', function() {
      expect(sender.pack(array)).to.eql(websafe);
    });

    it('recover', function() {
      expect(sender.unpack(websafe)).to.eql(array);
    });
  });

  describe('map', function() {
    var map = {'compatibility-key': 'This is the simple-secrets compatibility standard map.'};
    var websafe = 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXYKrvvhyLbyFTsndgOx5M5yockEUwdSgv6jG_JYpAiU5R37Y7OIZnF3IN2EWtaFSuJko0ajcvoYgDPeLMvjAJdRyBUYIKcvR-g56_p4O7Uef3yJRnfCprG6jUdMyDBai_';

    it('create', function() {
      expect(sender.pack(map)).to.eql(websafe);
    });

    it('recover', function() {
      expect(sender.unpack(websafe)).to.eql(map);
    });
  });

});
