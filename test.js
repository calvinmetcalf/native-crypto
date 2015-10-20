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
var Signature = require('./signature');
var jwk2pem = require('jwk-to-pem');

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
test('rsa', function (t) {
  var priv = {"alg":"RS256","d":"sdK3B7o5KLYyqtmJXOAjEAYEgxUgzBuNawX2jn0Gdq1KDmDve7jnWvqH15N6S79-nim_D9QCjdEnnW9G_x58aU0BBB4o5EGyR5jjViAaP_hqg2GpofYAdP0prP4v6Z5gAq7Dj0pOT9f4zMShhQrOdtYo_-Qm_O4QG420D-qnQgE","dp":"k0oeKJrXapFiBKQ_9h1hQk4NgYBlBeWBCFTUKkl2fHHDy6o4e8UYF2afGuIFUl8I678jmxt7rYNI_9YwC11OFw","dq":"bYkZ8wm-oo_1KNZVC3nKslFlCUYEAYFsCnMSc2nhos7YiBcpAEkSzCGRX0jhpeWiFfYPzVWLpRDDM11vG_KCgQ","e":"AQAB","ext":true,"key_ops":["sign"],"kty":"RSA","n":"1t4f0uvLHN-gszBOCpk_JOL-aOwqj5AziPXSY36LyMaK_b02VGAcyoNcGI8xYFempmOT3TztQGgqlgg7zbFE7TvKWQ2BLx8F41N0ErJmZlj1X_hNo93MEagOUQbkoq3QRC9RVjmnnjPHv4LA_kka_8wUPqYq1aFxpHptT2RX0-s","p":"9UDFpGn3kRGtAZUPtchOhFtKygv4oEfaDaHIb2OXX1I1Yg0nC3orBa7N8lyHz5W3XaehGtmcUpjTpFZMH2Kbaw","q":"4Eh99SLMOtLpYRpKD_Bv0QDFSknFJSGc7sG1dc8TOa3ielrSJD-oowHcEAvoqtY9sfx6l6RAfJ2yFQIr24JJgQ","qi":"P93LJwlJ-k4BGjY78HqNgLFR7eOTYoEDgG4zLHjo43PACBEDmkGzDGgK7c5M-VMgdrckTNDHPBkp7vxO4cqddg"};
  var pub = {"alg":"RS256","e":"AQAB","ext":true,"key_ops":["verify"],"kty":"RSA","n":"1t4f0uvLHN-gszBOCpk_JOL-aOwqj5AziPXSY36LyMaK_b02VGAcyoNcGI8xYFempmOT3TztQGgqlgg7zbFE7TvKWQ2BLx8F41N0ErJmZlj1X_hNo93MEagOUQbkoq3QRC9RVjmnnjPHv4LA_kka_8wUPqYq1aFxpHptT2RX0-s"};
  var nodePriv = jwk2pem(priv, {
    private: true
  });
  var nodePub = jwk2pem(pub);
  var data = new Buffer('fooooooo');
  var nodeSig = crypto.createSign('RSA-SHA256').update(data).sign(nodePriv);
  new Signature(priv).update(data).sign().then(function (sig) {
    t.ok(crypto.createVerify('RSA-SHA256').update(data).verify(nodePub, sig), 'node verify');
    t.equals(nodeSig.toString('hex'), sig.toString('hex'));
    return new Signature(pub, nodeSig).update(data).verify();
  }).then(function (res) {
    t.ok(res, 'we verify');
    t.end();
  }).catch(function (e) {
    t.error(e);
    t.end();
  });
})
