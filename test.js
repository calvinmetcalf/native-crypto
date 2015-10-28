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
    t.test('ecdsa p256', function (t) {
      var priv = {"crv":"P-256","d":"EbZoCsc-k8QhV4s6YjomZyB1qtgdA6dnOjKqOqx8OEE","ext":true,"key_ops":["sign"],"kty":"EC","x":"1lw1cUhf1bDx7Ij_WpRU7ZvrhZJMJOFxn0xc5JJDrEg","y":"HtJQX9tK8gllFtZjf-z7HRzLhosF9bgGS77L5pAcCsM"};
      var pub = {"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":"1lw1cUhf1bDx7Ij_WpRU7ZvrhZJMJOFxn0xc5JJDrEg","y":"HtJQX9tK8gllFtZjf-z7HRzLhosF9bgGS77L5pAcCsM"};
      var nodePriv = new Buffer(jwk2pem(priv, {
        private: true
      }));
      console.log(jwk2pem(pub));
      var nodePub = new Buffer(jwk2pem(pub));
      var data = new Buffer('fooooooo');
      var npriv = new raw.Key(nodePriv);
      var nodeSig = npriv.sign(crypto.createHash('sha256').update(data).digest());
      var roundtrip = toDER(fromDer(nodeSig, 32));
      t.equals(roundtrip.toString('hex'), nodeSig.toString('hex'), 'round trips');
      new Signature(priv).update(data).sign().then(function (sig) {
        var npub = new raw.Key(nodePub);
        var h = crypto.createHash('sha256').update(data).digest();
        t.ok(npub.verify(toDER(sig), h), 'node verify');
        return new Signature(pub, fromDer(nodeSig, 32)).update(data).verify();
      }).then(function (res) {
        t.ok(res, 'we verify');
        t.end();
      }).catch(function (e) {
        t.error(e);
        t.end();
      });
    });
    // t.test('ecdsa p384', function (t) {
    //   var priv = {"crv":"P-384","d":"Il-D741GZgCA5CRRzC5XIJh5zLB9ofnlX0GqB4Vrnp1eHJOhWxRuyimAr6HD-oyd","ext":true,"key_ops":["sign"],"kty":"EC","x":"-sJ_JrOrbzO3k-qZSEwItkl8_Dxk9dQhFh-y4akAYZHMSb0AjGROcEUC9A6_7NOh","y":"Hnms0caSuoofsHI86V1yw2hBzSYWSpGAaRe1ZcCgsFryQLjZvnVoKOa4Cg1X4GhN"};
    //   var pub = {"crv":"P-384","ext":true,"key_ops":["verify"],"kty":"EC","x":"-sJ_JrOrbzO3k-qZSEwItkl8_Dxk9dQhFh-y4akAYZHMSb0AjGROcEUC9A6_7NOh","y":"Hnms0caSuoofsHI86V1yw2hBzSYWSpGAaRe1ZcCgsFryQLjZvnVoKOa4Cg1X4GhN"};
    //   var nodePriv = jwk2pem(priv, {
    //     private: true
    //   });
    //   var nodePub = jwk2pem(pub);
    //   var data = new Buffer('fooooooo');
    //   var nodeSig = crypto.createSign('ecdsa-with-SHA1').update(data).sign(nodePriv);
    //   var roundtrip = toDER(fromDer(nodeSig, 48));
    //   t.equals(roundtrip.toString('hex'), nodeSig.toString('hex'), 'round trips');
    //   new Signature(priv).update(data).sign().then(function (sig) {
    //     t.ok(crypto.createVerify('ecdsa-with-SHA1').update(data).verify(nodePub, toDER(sig)), 'node verify');
    //     return new Signature(pub, fromDer(nodeSig, 48)).update(data).verify();
    //   }).then(function (res) {
    //     t.ok(res, 'we verify');
    //     t.end();
    //   }).catch(function (e) {
    //     t.error(e);
    //     t.end();
    //   });
    // });
    t.test('der', function (t) {
      var ders = [
        '308188024201715200ebada87d5e4e1b19b60b7ac8338f9e056289e19316bbf6accbb48375c6f5281db504ae35f56075d64ffe6186e8cb9ddff5aa5852ffd535589809c3024474024200a1b51d481385cdf6f047b79e8769ba31a3b50d1e072e3d75f2369ded67c41e0fe18a587acd5a5ce54ef1f7af79ba3664f0c31b7f117a75743f7bf0d6f3183e74e2',
        '30818702420184066ff7b0329adf370594c66e2072a1d72eb441520e7495d92a78c2a8f1472159840fc29d9085f80eb168f4eba7468edde024f5c853733993c5785504a0f13674024129cfe1b54bb0eb3dffcae33b1300d6c16aeb717cf5cfd8c0f87d38f6831da597fa5ba3c8b64e4805b320da7af906cd5ba036b93197f9a8ca8c6c589507deee316d'
      ];
      ders.forEach(function (str) {
        var out = toDER(fromDer(new Buffer(str, 'hex'), 66));
        t.equals(out.toString('hex'), str);
      });
      t.end();
    });
    // t.test('ecdsa p521', function (t) {
    //   var priv = {"crv":"P-521","d":"Af8h6dGJGbIp4Nmet-ZpV1mDJB3l5hw58lBfSL9Q1yXwLlonOWrIwSZIy2Udm9I_Lx9zP4W7A-oHcQXAekKAhCUx","ext":true,"key_ops":["sign"],"kty":"EC","x":"ARL4r-1H5vUinQSFVsEEfBunX_gwuyJ-Xk_nCCiP4ZTf2iaaSwJXzbPCObgr44eFHzHhzY0sxdnl3UmpDmwj0W1U","y":"AJ2LoHDZSHNDz-1c8y1LeQbS8h20IzCL-8w-oxwUv2en-1JrvAwjdhfn4xBMSCbPm7V5UOx-4sG0EkCCo16DuAO8"}
    //   var pub = {"crv":"P-521","ext":true,"key_ops":["verify"],"kty":"EC","x":"ARL4r-1H5vUinQSFVsEEfBunX_gwuyJ-Xk_nCCiP4ZTf2iaaSwJXzbPCObgr44eFHzHhzY0sxdnl3UmpDmwj0W1U","y":"AJ2LoHDZSHNDz-1c8y1LeQbS8h20IzCL-8w-oxwUv2en-1JrvAwjdhfn4xBMSCbPm7V5UOx-4sG0EkCCo16DuAO8"};
    //   var nodePriv = jwk2pem(priv, {
    //     private: true
    //   });
    //   var nodePub = jwk2pem(pub);
    //   var data = new Buffer('fooooooo');
    //   var nodeSig = crypto.createSign('ecdsa-with-SHA1').update(data).sign(nodePriv);
    //   var roundtrip = toDER(fromDer(nodeSig, 66));
    //   t.equals(roundtrip.toString('hex'), nodeSig.toString('hex'), 'round trips');
    //   new Signature(priv).update(data).sign().then(function (sig) {
    //     var ourDER = toDER(sig);
    //     t.ok(crypto.createVerify('ecdsa-with-SHA1').update(data).verify(nodePub, ourDER), 'node verify');
    //     return new Signature(pub, fromDer(nodeSig, 66)).update(data).verify();
    //   }).then(function (res) {
    //     t.ok(res, 'we verify');
    //     t.end();
    //   }).catch(function (e) {
    //     t.error(e);
    //     t.end();
    //   });
    // });
  });
}
var len = 5;
var i = 0;
while (++i < len) {
  runedsa(i);
}
