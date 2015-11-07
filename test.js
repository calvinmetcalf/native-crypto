'use strict';
var raw;
if (process.browser) {
  window.myDebug = require('debug');
  window.myDebug.enable('native-crypto:*');
} else {
  try {
    raw = require('raw-ecdsa');
  } catch(e){}
}
var base64url = require('./base64url');

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
var der = require('./der');
var fromDer = der.fromDer;
var toDER = der.toDER;
var EC = require('elliptic').ec;
test('hash', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  eachAlgo('sha1', t);
  eachAlgo('sha256', t);
  eachAlgo('sha384', t);
  eachAlgo('sha512', t);
  function eachAlgo(algo, t) {
    t.test(algo, function (t) {
      var nodeHash = crypto.createHash(algo).update(buf).digest().toString('hex');
      new Hash(algo).update(buf).digest().then(function (ourHash) {
        t.equals(nodeHash, ourHash.toString('hex'));
        t.end();
      }).catch(function (e) {
        t.ok(false, e.stack);
        t.end();
      });
    });
  }
});
test('hmac sign', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  eachAlgo('sha1', t);
  eachAlgo('sha256', t);
  eachAlgo('sha384', t);
  eachAlgo('sha512', t);
  function eachAlgo(algo, t) {
    t.test(algo, function (t) {
      var nodeHash = crypto.createHmac(algo, buf).update(buf).digest().toString('hex');
      new Hmac(algo, buf).update(buf).digest().then(function (ourHash) {
        t.equals(nodeHash, ourHash.toString('hex'), 'worked');
        t.end();
      }).catch(function (e) {
        t.ok(false, e.stack);
        t.end();
      });
    });
  }
});
test('hmac verify', function (t) {
  var buf = new Buffer(8);
  buf.fill(0);
  eachAlgo('sha1', t);
  eachAlgo('sha256', t);
  eachAlgo('sha384', t);
  eachAlgo('sha512', t);
  function eachAlgo(algo, t) {
    t.test(algo, function (t) {
      var nodeHash = crypto.createHmac(algo, buf).update(buf).digest();
      new Hmac(algo, buf, nodeHash).update(buf).verify().then(function (ourHash) {
        t.ok(ourHash, 'worked');
        t.end();
      }).catch(function (e) {
        t.ok(false, e.stack);
        t.end();
      });
    });
  }
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
});
function runedsa(i) {
  test('run ' + i, function (t) {
    var priv256 = {"crv":"P-256","d":"EbZoCsc-k8QhV4s6YjomZyB1qtgdA6dnOjKqOqx8OEE","ext":true,"key_ops":["sign"],"kty":"EC","x":"1lw1cUhf1bDx7Ij_WpRU7ZvrhZJMJOFxn0xc5JJDrEg","y":"HtJQX9tK8gllFtZjf-z7HRzLhosF9bgGS77L5pAcCsM"};
    var pub256 = {"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"1lw1cUhf1bDx7Ij_WpRU7ZvrhZJMJOFxn0xc5JJDrEg","y":"HtJQX9tK8gllFtZjf-z7HRzLhosF9bgGS77L5pAcCsM"};
    var priv384 = {"crv":"P-384","d":"Il-D741GZgCA5CRRzC5XIJh5zLB9ofnlX0GqB4Vrnp1eHJOhWxRuyimAr6HD-oyd","ext":true,"key_ops":["sign"],"kty":"EC","x":"-sJ_JrOrbzO3k-qZSEwItkl8_Dxk9dQhFh-y4akAYZHMSb0AjGROcEUC9A6_7NOh","y":"Hnms0caSuoofsHI86V1yw2hBzSYWSpGAaRe1ZcCgsFryQLjZvnVoKOa4Cg1X4GhN"};
    var pub384 = {"crv":"P-384","ext":true,"key_ops":["verify"],"kty":"EC","x":"-sJ_JrOrbzO3k-qZSEwItkl8_Dxk9dQhFh-y4akAYZHMSb0AjGROcEUC9A6_7NOh","y":"Hnms0caSuoofsHI86V1yw2hBzSYWSpGAaRe1ZcCgsFryQLjZvnVoKOa4Cg1X4GhN"};
    var priv521 = {"crv":"P-521","d":"Af8h6dGJGbIp4Nmet-ZpV1mDJB3l5hw58lBfSL9Q1yXwLlonOWrIwSZIy2Udm9I_Lx9zP4W7A-oHcQXAekKAhCUx","ext":true,"key_ops":["sign"],"kty":"EC","x":"ARL4r-1H5vUinQSFVsEEfBunX_gwuyJ-Xk_nCCiP4ZTf2iaaSwJXzbPCObgr44eFHzHhzY0sxdnl3UmpDmwj0W1U","y":"AJ2LoHDZSHNDz-1c8y1LeQbS8h20IzCL-8w-oxwUv2en-1JrvAwjdhfn4xBMSCbPm7V5UOx-4sG0EkCCo16DuAO8"}
    var pub521 = {"crv":"P-521","ext":true,"key_ops":["verify"],"kty":"EC","x":"ARL4r-1H5vUinQSFVsEEfBunX_gwuyJ-Xk_nCCiP4ZTf2iaaSwJXzbPCObgr44eFHzHhzY0sxdnl3UmpDmwj0W1U","y":"AJ2LoHDZSHNDz-1c8y1LeQbS8h20IzCL-8w-oxwUv2en-1JrvAwjdhfn4xBMSCbPm7V5UOx-4sG0EkCCo16DuAO8"};

    if (process.browser) {
      runTestBrowser('p256', 'sha256', 32, priv256, pub256);
      runTestBrowser('p384', 'sha384', 48, priv384, pub384);
      runTestBrowser('p521', 'sha512', 66, priv521, pub521);
    } else {
      runTestNode('p256', 'sha256', 32, priv256, pub256);
      runTestNode('p384', 'sha384', 48, priv384, pub384);
      runTestNode('p521', 'sha512', 66, priv521, pub521);
    }
    function runTestNode(curve, hash, bitLen, priv, pub) {
      t.test('ecdsa ' + curve, function (t) {
                var nodePriv = new Buffer(jwk2pem(priv, {
          private: true
        }));
        var nodePub = new Buffer(jwk2pem(pub));
        var data = new Buffer('fooooooo');
        var npriv = new raw.Key(nodePriv);
        var nodeSig = npriv.sign(crypto.createHash(hash).update(data).digest());
        var roundtrip = toDER(fromDer(nodeSig, bitLen));
        t.equals(roundtrip.toString('hex'), nodeSig.toString('hex'), 'round trips');
        new Signature(priv).update(data).sign().then(function (sig) {
          var npub = new raw.Key(nodePub);
          var h = crypto.createHash(hash).update(data).digest();
          t.ok(npub.verify(toDER(sig), h), 'node verify');
          return new Signature(pub, fromDer(nodeSig, bitLen)).update(data).verify();
        }).then(function (res) {
          t.ok(res, 'we verify');
          t.end();
        }).catch(function (e) {
          t.error(e);
          t.end();
        });
      });
    }
    function runTestBrowser(curve, hash, bitLen, priv, pub) {
      t.test('ecdsa ' + curve, function (t) {
                var nodePriv = new Buffer(jwk2pem(priv, {
          private: true
        }));
        let ec = new EC(curve);
        var data = new Buffer('fooooooo');
        var npriv = ec.keyFromPrivate(base64url.decode(priv.d));
        var nodeSig = new Buffer(npriv.sign(crypto.createHash(hash).update(data).digest()).toDER());
        var roundtrip = toDER(fromDer(nodeSig, bitLen));
        t.equals(roundtrip.toString('hex'), nodeSig.toString('hex'), 'round trips');
        new Signature(priv).update(data).sign().then(function (sig) {
          var h = crypto.createHash(hash).update(data).digest();
          t.ok(ec.verify(h, toDER(sig), {
            x: base64url.decode(pub.x).toString('hex'),
            y: base64url.decode(pub.y).toString('hex')
          }), 'node verify');
          return new Signature(pub, fromDer(nodeSig, bitLen)).update(data).verify();
        }).then(function (res) {
          t.ok(res, 'we verify');
          t.end();
        }).catch(function (e) {
          t.error(e);
          t.end();
        });
      });
    }
  });
}
var len = 5;
var i = 0;
while (++i < len) {
  runedsa(i);
}
