'use strict';
if (process.browser) {
  window.myDebug = require('debug');
  window.myDebug.enable('native-crypto:*');
}
var jwk = require('./jwk');
var crypto = require('crypto');
var test = require('tape');
var Hash = require('./hash');
var Hmac = require('./hmac');
var encrypt = require('./encrypt');
var decrypt = require('./decrypt');
var ECDH = require('./ecdh');
test('hash', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  var nodeHash = crypto.createHash('sha256').update(buf).digest().toString('hex');
  new Hash('sha-256').update(buf).digest().then(function (ourHash) {
    t.equals(nodeHash, ourHash.toString('hex'));
    t.end();
  }).catch(function (e) {
    t.ok(false, e.stack);
    t.end();
  });
});
test('hmac sign', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  var nodeHash = crypto.createHmac('sha256', buf).update(buf).digest().toString('hex');
  new Hmac('sha-256', buf).update(buf).digest().then(function (ourHash) {
    t.equals(nodeHash, ourHash.toString('hex'), 'worked');
    t.end();
  }).catch(function (e) {
    t.ok(false, e.stack);
    t.end();
  });
});
test('hmac verify', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  var nodeHash = crypto.createHmac('sha256', buf).update(buf).digest();
  new Hmac('sha-256', buf, nodeHash).update(buf).verify().then(function (ourHash) {
    t.ok(ourHash, 'worked');
    t.end();
  }).catch(function (e) {
    t.ok(false, e.stack);
    t.end();
  });
});
test('encrypt/decrypt', function (t) {
  var key = new Buffer(16);
  var iv = new Buffer(12);
  var aad = new Buffer(8);
  var data = new Buffer(64);
  key.fill(0);
  iv.fill(0);
  aad.fill(0);
  data.fill(0);
  var nodeCipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  nodeCipher.setAAD(aad);
  var out = nodeCipher.update(data);
  nodeCipher.final();
  var tag = nodeCipher.getAuthTag();
  var expected = Buffer.concat([out, tag]).toString('hex');
  encrypt(key, iv, data, aad).then(function (res) {
    t.equals(res.toString('hex'), expected, 'encrypted');
    return decrypt(key, iv, res, aad);
  }).then(function (res) {
    t.equals(res.toString('hex'), data.toString('hex'), 'decrypted');
    t.end();
  }).catch(function (e) {
    t.error(e);
    t.end();
  });
});
test('ecdh p-256', function (t) {
  var nodeECDH = crypto.createECDH('prime256v1');
  var ourECDH = new ECDH('prime256v1');
  var nodePublic, ourPublic;
  ourECDH.getPublic().then(function (_ourPublic) {
    ourPublic = _ourPublic;
    nodePublic = nodeECDH.generateKeys();
    return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-256'));
  }).then(function (ourValue) {
    var nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
    t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
    t.end();
  }).catch(function (e) {
    t.error(e);
    t.end();
  });
});
test('ecdh p-256 with privatekeys', function (t) {
  var nodeECDH = crypto.createECDH('prime256v1');
  var ourECDH = new ECDH('prime256v1');
  ourECDH.getPrivate().then(function (priv) {
    var ourECDH2 = new ECDH('prime256v1', priv);
    var nodePublic, ourPublic, nodeValue;
    ourECDH.getPublic().then(function (_ourPublic) {
      ourPublic = _ourPublic;
      nodePublic = nodeECDH.generateKeys();
      return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-256'));
    }).then(function (ourValue) {
      nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
      t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
      return ourECDH2.getPublic();
    }).then(function (pub){
      var ourValue2 = nodeECDH.computeSecret(jwk.fromJwk(pub));
      t.equals(ourValue2.toString('hex'), nodeValue.toString('hex'));
      t.end();
    }).catch(function (e) {
      t.error(e);
      t.end();
    });
  });
});
if (!process.browser) {
  test('ecdh p-384', function (t) {
    var nodeECDH = crypto.createECDH('secp384r1');
    var ourECDH = new ECDH('secp384r1');
    var nodePublic, ourPublic;
    ourECDH.getPublic().then(function (_ourPublic) {
      ourPublic = _ourPublic;
      nodePublic = nodeECDH.generateKeys();
      return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-384'));
    }).then(function (ourValue) {
      var nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
      t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
      t.end();
    }).catch(function (e) {
      t.error(e);
      t.end();
    });
  });
  test('ecdh p-521', function (t) {
    var nodeECDH = crypto.createECDH('secp521r1');
    var ourECDH = new ECDH('secp521r1');
    var nodePublic, ourPublic;
    ourECDH.getPublic().then(function (_ourPublic) {
      ourPublic = _ourPublic;
      nodePublic = nodeECDH.generateKeys();
      return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-521'));
    }).then(function (ourValue) {
      var nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
      t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
      t.end();
    }).catch(function (e) {
      t.error(e);
      t.end();
    });
  });
}
