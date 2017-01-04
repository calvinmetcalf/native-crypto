
var test = require('tape');
var randomBytes = require('randombytes');
var generate = require('../generate');
var Signature = require('../signature');

test('test ecdsa', function (t) {
  function testECDSA(type) {
    t.test(type, function (t) {
      t.plan(1);
      var pair;
      var data = randomBytes(100);
      generate(type).then(function (_pair) {
        pair = _pair;
        return new Signature(pair.privateKey).update(data).sign();
      }).then(function (sig) {
        return new Signature(pair.publicKey, sig).update(data).verify();
      }).then(function (worked) {
        t.ok(worked);
      }, function (e) {
        t.ok(false, e.stack);
      });
    });
  }
  testECDSA('P-256');
  testECDSA('P-384');
  testECDSA('P-521');
});

test('test rsa', function (t) {
  function testRSA(type, len, e) {
    t.test(`type: ${type}, len: ${len ? len: 'default len'}, e: ${e ? typeof e === 'number' ? e : e.toString('hex') : 'default e'}`, function (t) {
      t.plan(1);
      var pair;
      var data = randomBytes(100);
      generate(type, len, e).then(function (_pair) {
        pair = _pair;
        return new Signature(pair.privateKey).update(data).sign();
      }).then(function (sig) {
        return new Signature(pair.publicKey, sig).update(data).verify();
      }).then(function (worked) {
        t.ok(worked, 'worked to verify what we signed');
      }, function (e) {
        t.error(e || new Error('should be here'));
      });
    });
  }
  var algos = ['rs256', 'rs384', 'rs512'];
  var lens = [1024, 2048, 4096, null];
  var es = [3, new Buffer([5]), 0x10001, null];
  var i = -1;
  var algo, len, e, j, k;
  while (++i < algos.length) {
    algo = algos[i];
    j = -1;
    while (++j < lens.length) {
      len = lens[j];
      k = -1;
      while (++k < es.length) {
        e = es[k];
        testRSA(algo, len, e);
      }
    }
  }
});
