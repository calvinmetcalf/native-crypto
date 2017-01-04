'use strict';
var raw;
if (process.browser) {
  window.myDebug = require('debug');
  window.myDebug.enable('native-crypto:*');
} else {
  try {
    raw = require('raw-ecdsa');
  } catch (e) {}
}
var base64url = require('../lib/base64url');

var jwk = require('../lib/jwk');
var crypto = require('crypto');
var test = require('tape');
var Hash = require('../hash');
var Hmac = require('../hmac');
var encrypt = require('../encrypt');
var decrypt = require('../decrypt');
var ECDH = require('../lib/ecdh');
var Signature = require('../signature');
var jwk2pem = require('jwk-to-pem');
var format = require('ecdsa-sig-formatter');
var fromDer = format.derToJose;
var toDer = format.joseToDer;
var EC = require('elliptic').ec;
var rsa = require('../rsa');
var pbkdf2Fixtures = require('./pbkdf2-fixtures.json');
require('./test-generate');
// from the node module pbkdf2
var pbkdf2 = require('../pbkdf2');
test('hash', function(t) {
  var buf = new Buffer(8);
  buf.fill(0);
  eachAlgo('sha1', t);
  eachAlgo('sha256', t);
  eachAlgo('sha384', t);
  eachAlgo('sha512', t);

  function eachAlgo(algo, t) {
    t.test(algo, function(t) {
      var nodeHash = crypto.createHash(algo).update(buf).digest().toString('hex');
      new Hash(algo).update(buf).digest().then(function(ourHash) {
        t.equals(nodeHash, ourHash.toString('hex'));
        t.end();
      }).catch(function(e) {
        t.ok(false, e.stack);
        t.end();
      });
    });
  }
});
test('hmac sign', function(t) {
  var buf = new Buffer(8);
  buf.fill(0);
  eachAlgo('sha1', t);
  eachAlgo('sha256', t);
  eachAlgo('sha384', t);
  eachAlgo('sha512', t);

  function eachAlgo(algo, t) {
    t.test(algo, function(t) {
      var nodeHash = crypto.createHmac(algo, buf).update(buf).digest().toString('hex');
      new Hmac(algo, buf).update(buf).digest().then(function(ourHash) {
        t.equals(nodeHash, ourHash.toString('hex'), 'worked');
        t.end();
      }).catch(function(e) {
        t.ok(false, e.stack);
        t.end();
      });
    });
  }
});
test('hmac verify', function(t) {
  var buf = new Buffer(8);
  buf.fill(0);
  eachAlgo('sha1', t);
  eachAlgo('sha256', t);
  eachAlgo('sha384', t);
  eachAlgo('sha512', t);

  function eachAlgo(algo, t) {
    t.test(algo, function(t) {
      var nodeHash = crypto.createHmac(algo, buf).update(buf).digest();
      new Hmac(algo, buf, nodeHash).update(buf).verify().then(function(ourHash) {
        t.ok(ourHash, 'worked');
        t.end();
      }).catch(function(e) {
        t.ok(false, e.stack);
        t.end();
      });
    });
  }
});
test('encrypt/decrypt', function(t) {
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
  encrypt(key, iv, data, aad).then(function(res) {
    t.equals(res.toString('hex'), expected, 'encrypted');
    return decrypt(key, iv, res, aad);
  }).then(function(res) {
    t.equals(res.toString('hex'), data.toString('hex'), 'decrypted');
    t.end();
  }).catch(function(e) {
    t.error(e);
    t.end();
  });
});
test('ecdh p-256', function(t) {
  var nodeECDH = crypto.createECDH('prime256v1');
  var ourECDH = new ECDH('prime256v1');
  var nodePublic, ourPublic;
  ourECDH.getPublic().then(function(_ourPublic) {
    ourPublic = _ourPublic;
    nodePublic = nodeECDH.generateKeys();
    return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-256'));
  }).then(function(ourValue) {
    var nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
    t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
    t.end();
  }).catch(function(e) {
    t.error(e);
    t.end();
  });
});
test('ecdh p-256 with privatekeys', function(t) {
  var nodeECDH = crypto.createECDH('prime256v1');
  var ourECDH = new ECDH('prime256v1');
  ourECDH.getPrivate().then(function(priv) {
    var ourECDH2 = new ECDH('prime256v1', priv);
    var nodePublic, ourPublic, nodeValue;
    ourECDH.getPublic().then(function(_ourPublic) {
      ourPublic = _ourPublic;
      nodePublic = nodeECDH.generateKeys();
      return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-256'));
    }).then(function(ourValue) {
      nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
      t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
      return ourECDH2.getPublic();
    }).then(function(pub) {
      var ourValue2 = nodeECDH.computeSecret(jwk.fromJwk(pub));
      t.equals(ourValue2.toString('hex'), nodeValue.toString('hex'));
      t.end();
    }).catch(function(e) {
      t.error(e);
      t.end();
    });
  });
});
if (!process.browser) {
  test('ecdh p-384', function(t) {
    var nodeECDH = crypto.createECDH('secp384r1');
    var ourECDH = new ECDH('secp384r1');
    var nodePublic, ourPublic;
    ourECDH.getPublic().then(function(_ourPublic) {
      ourPublic = _ourPublic;
      nodePublic = nodeECDH.generateKeys();
      return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-384'));
    }).then(function(ourValue) {
      var nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
      t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
      t.end();
    }).catch(function(e) {
      t.error(e);
      t.end();
    });
  });
  test('ecdh p-521', function(t) {
    var nodeECDH = crypto.createECDH('secp521r1');
    var ourECDH = new ECDH('secp521r1');
    var nodePublic, ourPublic;
    ourECDH.getPublic().then(function(_ourPublic) {
      ourPublic = _ourPublic;
      nodePublic = nodeECDH.generateKeys();
      return ourECDH.computeSecret(jwk.toJwk(nodePublic, 'P-521'));
    }).then(function(ourValue) {
      var nodeValue = nodeECDH.computeSecret(jwk.fromJwk(ourPublic));
      t.equals(ourValue.toString('hex'), nodeValue.toString('hex'));
      t.end();
    }).catch(function(e) {
      t.error(e);
      t.end();
    });
  });
}
test('rsa', function(t) {
  var priv = {
    'alg': 'RS256',
    'd': 'sdK3B7o5KLYyqtmJXOAjEAYEgxUgzBuNawX2jn0Gdq1KDmDve7jnWvqH15N6S79-nim_D9QCjdEnnW9G_x58aU0BBB4o5EGyR5jjViAaP_hqg2GpofYAdP0prP4v6Z5gAq7Dj0pOT9f4zMShhQrOdtYo_-Qm_O4QG420D-qnQgE',
    'dp': 'k0oeKJrXapFiBKQ_9h1hQk4NgYBlBeWBCFTUKkl2fHHDy6o4e8UYF2afGuIFUl8I678jmxt7rYNI_9YwC11OFw',
    'dq': 'bYkZ8wm-oo_1KNZVC3nKslFlCUYEAYFsCnMSc2nhos7YiBcpAEkSzCGRX0jhpeWiFfYPzVWLpRDDM11vG_KCgQ',
    'e': 'AQAB',
    'ext': true,
    'key_ops': ['sign'],
    'kty': 'RSA',
    'n': '1t4f0uvLHN-gszBOCpk_JOL-aOwqj5AziPXSY36LyMaK_b02VGAcyoNcGI8xYFempmOT3TztQGgqlgg7zbFE7TvKWQ2BLx8F41N0ErJmZlj1X_hNo93MEagOUQbkoq3QRC9RVjmnnjPHv4LA_kka_8wUPqYq1aFxpHptT2RX0-s',
    'p': '9UDFpGn3kRGtAZUPtchOhFtKygv4oEfaDaHIb2OXX1I1Yg0nC3orBa7N8lyHz5W3XaehGtmcUpjTpFZMH2Kbaw',
    'q': '4Eh99SLMOtLpYRpKD_Bv0QDFSknFJSGc7sG1dc8TOa3ielrSJD-oowHcEAvoqtY9sfx6l6RAfJ2yFQIr24JJgQ',
    'qi': 'P93LJwlJ-k4BGjY78HqNgLFR7eOTYoEDgG4zLHjo43PACBEDmkGzDGgK7c5M-VMgdrckTNDHPBkp7vxO4cqddg'
  };
  var pub = {
    'alg': 'RS256',
    'e': 'AQAB',
    'ext': true,
    'key_ops': ['verify'],
    'kty': 'RSA',
    'n': '1t4f0uvLHN-gszBOCpk_JOL-aOwqj5AziPXSY36LyMaK_b02VGAcyoNcGI8xYFempmOT3TztQGgqlgg7zbFE7TvKWQ2BLx8F41N0ErJmZlj1X_hNo93MEagOUQbkoq3QRC9RVjmnnjPHv4LA_kka_8wUPqYq1aFxpHptT2RX0-s'
  };
  var nodePriv = jwk2pem(priv, {
    private: true
  });
  var nodePub = jwk2pem(pub);
  var data = new Buffer('fooooooo');
  var nodeSig = crypto.createSign('RSA-SHA256').update(data).sign(nodePriv);
  new Signature(priv).update(data).sign().then(function(sig) {
    t.ok(crypto.createVerify('RSA-SHA256').update(data).verify(nodePub, sig), 'node verify');
    t.equals(nodeSig.toString('hex'), sig.toString('hex'));
    return new Signature(pub, nodeSig).update(data).verify();
  }).then(function(res) {
    t.ok(res, 'we verify');
    t.end();
  }).catch(function(e) {
    t.error(e);
    t.end();
  });
});

function runedsa(i) {
  test('run ' + i, function(t) {
    var priv256 = {
      'crv': 'P-256',
      'd': 'EbZoCsc-k8QhV4s6YjomZyB1qtgdA6dnOjKqOqx8OEE',
      'ext': true,
      'key_ops': ['sign'],
      'kty': 'EC',
      'x': '1lw1cUhf1bDx7Ij_WpRU7ZvrhZJMJOFxn0xc5JJDrEg',
      'y': 'HtJQX9tK8gllFtZjf-z7HRzLhosF9bgGS77L5pAcCsM'
    };
    var pub256 = {
      'crv': 'P-256',
      'ext': true,
      'key_ops': ['verify'],
      'kty': 'EC',
      'x': '1lw1cUhf1bDx7Ij_WpRU7ZvrhZJMJOFxn0xc5JJDrEg',
      'y': 'HtJQX9tK8gllFtZjf-z7HRzLhosF9bgGS77L5pAcCsM'
    };
    var priv384 = {
      'crv': 'P-384',
      'd': 'Il-D741GZgCA5CRRzC5XIJh5zLB9ofnlX0GqB4Vrnp1eHJOhWxRuyimAr6HD-oyd',
      'ext': true,
      'key_ops': ['sign'],
      'kty': 'EC',
      'x': '-sJ_JrOrbzO3k-qZSEwItkl8_Dxk9dQhFh-y4akAYZHMSb0AjGROcEUC9A6_7NOh',
      'y': 'Hnms0caSuoofsHI86V1yw2hBzSYWSpGAaRe1ZcCgsFryQLjZvnVoKOa4Cg1X4GhN'
    };
    var pub384 = {
      'crv': 'P-384',
      'ext': true,
      'key_ops': ['verify'],
      'kty': 'EC',
      'x': '-sJ_JrOrbzO3k-qZSEwItkl8_Dxk9dQhFh-y4akAYZHMSb0AjGROcEUC9A6_7NOh',
      'y': 'Hnms0caSuoofsHI86V1yw2hBzSYWSpGAaRe1ZcCgsFryQLjZvnVoKOa4Cg1X4GhN'
    };
    var priv521 = {
      'crv': 'P-521',
      'd': 'Af8h6dGJGbIp4Nmet-ZpV1mDJB3l5hw58lBfSL9Q1yXwLlonOWrIwSZIy2Udm9I_Lx9zP4W7A-oHcQXAekKAhCUx',
      'ext': true,
      'key_ops': ['sign'],
      'kty': 'EC',
      'x': 'ARL4r-1H5vUinQSFVsEEfBunX_gwuyJ-Xk_nCCiP4ZTf2iaaSwJXzbPCObgr44eFHzHhzY0sxdnl3UmpDmwj0W1U',
      'y': 'AJ2LoHDZSHNDz-1c8y1LeQbS8h20IzCL-8w-oxwUv2en-1JrvAwjdhfn4xBMSCbPm7V5UOx-4sG0EkCCo16DuAO8'
    }
    var pub521 = {
      'crv': 'P-521',
      'ext': true,
      'key_ops': ['verify'],
      'kty': 'EC',
      'x': 'ARL4r-1H5vUinQSFVsEEfBunX_gwuyJ-Xk_nCCiP4ZTf2iaaSwJXzbPCObgr44eFHzHhzY0sxdnl3UmpDmwj0W1U',
      'y': 'AJ2LoHDZSHNDz-1c8y1LeQbS8h20IzCL-8w-oxwUv2en-1JrvAwjdhfn4xBMSCbPm7V5UOx-4sG0EkCCo16DuAO8'
    };

    if (process.browser) {
      runTestBrowser('p256', 'sha256', priv256, pub256);
      runTestBrowser('p384', 'sha384', priv384, pub384);
      runTestBrowser('p521', 'sha512', priv521, pub521);
    } else {
      runTestNode('p256', 'sha256', priv256, pub256);
      runTestNode('p384', 'sha384', priv384, pub384);
      runTestNode('p521', 'sha512', priv521, pub521);
    }
    var otherECNames = {
      'p256': 'ES256',
      'p384': 'ES384',
      'p521': 'ES512'
    }
    function runTestNode(curve, hash, priv, pub) {
      t.test('ecdsa ' + curve, function(t) {
        var nodePriv = new Buffer(jwk2pem(priv, {
          private: true
        }));
        var nodePub = new Buffer(jwk2pem(pub));
        var data = new Buffer('fooooooo');
        var npriv = new raw.Key(nodePriv);
        var nodeSig = npriv.sign(crypto.createHash(hash).update(data).digest());
        var roundtrip = toDer(new Buffer(fromDer(nodeSig, otherECNames[curve]), 'base64'), otherECNames[curve]);
        t.equals(roundtrip.toString('hex'), nodeSig.toString('hex'), 'round trips');
        new Signature(priv).update(data).sign().then(function(sig) {
          var npub = new raw.Key(nodePub);
          var h = crypto.createHash(hash).update(data).digest();
          t.ok(npub.verify(toDer(sig, otherECNames[curve]), h), 'node verify');
          return new Signature(pub, new Buffer(fromDer(nodeSig, otherECNames[curve]), 'base64')).update(data).verify();
        }).then(function(res) {
          t.ok(res, 'we verify');
          t.end();
        }).catch(function(e) {
          t.error(e);
          t.end();
        });
      });
    }

    function runTestBrowser(curve, hash, priv, pub) {
      t.test('ecdsa ' + curve, function(t) {
        var nodePriv = new Buffer(jwk2pem(priv, {
          private: true
        }));
        let ec = new EC(curve);
        var data = new Buffer('fooooooo');
        var npriv = ec.keyFromPrivate(base64url.decode(priv.d));
        var nodeSig = new Buffer(npriv.sign(crypto.createHash(hash).update(data).digest()).toDER());
        var roundtrip = toDer(new Buffer(fromDer(nodeSig, otherECNames[curve]), 'base64'), otherECNames[curve]);
        t.equals(roundtrip.toString('hex'), nodeSig.toString('hex'), 'round trips');
        new Signature(priv).update(data).sign().then(function(sig) {
          var h = crypto.createHash(hash).update(data).digest();
          t.ok(ec.verify(h, toDer(sig, otherECNames[curve]), {
            x: base64url.decode(pub.x).toString('hex'),
            y: base64url.decode(pub.y).toString('hex')
          }), 'node verify');
          return new Signature(pub, new Buffer(fromDer(nodeSig, otherECNames[curve]), 'base64')).update(data).verify();
        }).then(function(res) {
          t.ok(res, 'we verify');
          t.end();
        }).catch(function(e) {
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
test('pbkdf2', function(t) {
  pbkdf2Fixtures.forEach(function(fixture, i) {
    t.test('fixture: ' + i, function(t) {
      var key, salt;
      if (fixture.key) {
        key = new Buffer(fixture.key, 'binary');
      } else if (fixture.keyHex) {
        key = new Buffer(fixture.keyHex, 'hex');
      }
      if (fixture.salt) {
        salt = new Buffer(fixture.salt, 'binary');
      } else if (fixture.saltHex) {
        salt = new Buffer(fixture.saltHex, 'hex');
      }
      var length = fixture.dkLen;
      var iterations = fixture.iterations;
      Object.keys(fixture.results).forEach(function(algo) {
        t.test(algo, function(t) {
          t.plan(1);
          var result = fixture.results[algo];
          pbkdf2(key, salt, iterations, length, algo).then(function(res) {
            t.equals(res.toString('hex'), result);
          }, function(err) {
            t.notOk(err || true);
          });
        });
      });
    });
    t.test('fixture text: ' + i, function(t) {
      var key, salt;
      if (fixture.key) {
        key = fixture.key;
      } else if (fixture.keyHex) {
        key = new Buffer(fixture.keyHex, 'hex');
      }
      if (fixture.salt) {
        salt = new Buffer(fixture.salt, 'binary');
      } else if (fixture.saltHex) {
        salt = new Buffer(fixture.saltHex, 'hex');
      }
      var length = fixture.dkLen;
      var iterations = fixture.iterations;
      Object.keys(fixture.results).forEach(function(algo) {
        t.test(algo, function(t) {
          t.plan(1);
          var result = fixture.results[algo];
          pbkdf2(key, salt, iterations, length, algo).then(function(res) {
            t.equals(res.toString('hex'), result);
          }, function(err) {
            t.error(err || true, 'should be no error');
          });
        });
      });
    });
  });
});
test('rsa', function(t) {
  var jwkKeys = {
    'private': {
      'alg': 'RSA-OAEP',
      'd': 'cy41l5g8Wjyxzy_O-JrwHUtfgLkYOu4FsqR6TnhnUcHghhp4kDHs-xiUzMCKxCKUzs4m4B6vTeBGfVsggug2f4L1I4PidXw7Bl_to8A2Oggu9GHeWCiQvIIXFVZKo930QmYGBnvSO50yYFRXHl403a-bYtB36j1OylajJ4wWI1SquaqoYq26rggJY3F4Pv4MzO0CNmchxKnYRMM94fkI-TUkOwvh39AhE1zrCzEC_D_O2OTyZA0qDSYt5ylwSp3NsSA_IXaP86gfHikrySCW7Xs56UVagNhdEOI8738R0TWfR3RU9yFsgx62GpuLg3XOSqBCKpvlib6IfJN1cnX74Q',
      'dp': 'pofEZI0RbklsReHuhT4N1xpoWtKzL2y_kGl-k-IVP6DvL1les9hiQomZBQkDpU89FeT3r_K8J_XJFgbRr_4ZOVEtybK78FFRrii2Vl2jrXhOalBppxv_OEuJFTXwqbDRrIc3PVrYJABLKa3k0eNwMsypCcBFhQJ_aPnrmGTlwRk',
      'dq': 'OXNF5cF02vGDFludOO8mh70QINyTg_gIxpEHObTsNotQ_BMFRzllgFAV5cFOXwjLF-pgTnWUug9IaW7Fx3E-T-1hP7X2ZlIo_DdqosNnlogJgf1LeG2rPdec05eNLPYim54XPf9HIHGegEEYwNc1tI6TerMrYRobfX_ANAH3l00',
      'e': 'AQAB',
      'ext': true,
      'key_ops': [
        'decrypt'
      ],
      'kty': 'RSA',
      'n': 't3H10hxU2VQn3YTrPftwI-f3RBIlsFG6EHmep7SiSicfCbSHBMZXlvgqr7XKFyn-TdJoi1d_uG143wfuazjnCECUwQpodsstnLBvm6ZNHuQqdSbuYA_7WmghJLub8zzTjRHQb2XEIpyaMrIP-w5cNhpyeXOAuqvZ2UzMeF1nj_D2k05dkpUDQFrnnayxUhFYVy2Ee4az5ep7sYsTGUOFV8xIGPyxhpKZX-Qqmawo_S27RmYvqVhEH8eVicLU2E3McFSkXGvr2e4PB9bge7uauus1MV2x27JCmrAlQHRXYCETm7aBwZ2fs6AIJD2Btky-bbg7RLKZS9VyN_K6nABobQ',
      'p': '6i3AI_Q75E8ihP86Stm0FR3JEOhdIOh1AbbRK0LDJxsAn0ycW9DFoZjUG-_8eayYzHtQoBm6ytgcO5v13UtSIhpDMeJyILZKL2rhJuJ26wASHoYEclnNCa1h3IVhMjVa8Y2JQYxQskhFnidrmcQmJ86KVliCf4OTUvqJojc3V3k',
      'q': 'yIn6llUXeLeOjcK3yDXFDcCYP8SAV2wmiofNpEq_L1I6KMTo-TuG_2h2NvBVvhOG--p1oNM5hZVvH2QAyzR6darL3EPglqYYDrs_4hXEOP1lbqkDlQ-3gkSs_fI9LJ5TVa3foZ_jMuIHeGgTxSZx56bFpTLfs7fL2pMlgcubt5U',
      'qi': 'mLUv01qhMus7cnkwAqAZ8oQDMhvliZ9CmFjHtQUUnHCJDH3Y_oHAEZcYSYD97Cc_qzCszidxUpWZ46aq9AuC_ivIax7Pp-4q2S2XZZ3TFsB5kDCLkOJJvcw6AyYE5Fg_iFQuyC4rssvQij4ANshLQZEyqcQpkFpDixLf2LAykn8'
    },
    'public': {
      'alg': 'RSA-OAEP',
      'e': 'AQAB',
      'ext': true,
      'key_ops': [
        'encrypt'
      ],
      'kty': 'RSA',
      'n': 't3H10hxU2VQn3YTrPftwI-f3RBIlsFG6EHmep7SiSicfCbSHBMZXlvgqr7XKFyn-TdJoi1d_uG143wfuazjnCECUwQpodsstnLBvm6ZNHuQqdSbuYA_7WmghJLub8zzTjRHQb2XEIpyaMrIP-w5cNhpyeXOAuqvZ2UzMeF1nj_D2k05dkpUDQFrnnayxUhFYVy2Ee4az5ep7sYsTGUOFV8xIGPyxhpKZX-Qqmawo_S27RmYvqVhEH8eVicLU2E3McFSkXGvr2e4PB9bge7uauus1MV2x27JCmrAlQHRXYCETm7aBwZ2fs6AIJD2Btky-bbg7RLKZS9VyN_K6nABobQ'
    }
  };
  var pemKeys = {
    public: jwk2pem(jwkKeys.public),
    private: jwk2pem(jwkKeys.private, {
      private: true
    })
  };
  t.test('we encrypt, we decrypt', function (t) {
    t.plan(1);
    var data = new Buffer('we encrypt, we decrypt');
    rsa.encrypt(jwkKeys.public, data).then(resp=>{
      return rsa.decrypt(jwkKeys.private, resp);
    }).then(function (decrypt) {
      t.equals(decrypt.toString(), 'we encrypt, we decrypt');
    }).catch(function (e) {
      t.error(e||'error');
    });
  });
  t.test('we encrypt, node decrypts', function (t) {
    t.plan(1);
    var data = new Buffer('we encrypt, node decrypts');
    rsa.encrypt(jwkKeys.public, data).then(resp=>{
      var decrypt = crypto.privateDecrypt(pemKeys.private, resp);
      t.equals(decrypt.toString(), 'we encrypt, node decrypts');
    }).catch(function (e) {
      t.error(e||'error');
    });
  });
  t.test('node encrypt, we decrypt', function (t) {
    t.plan(1);
    var data = new Buffer('node encrypt, we decrypt');
    var encrypted = crypto.publicEncrypt(pemKeys.public, data);
    rsa.decrypt(jwkKeys.private, encrypted).then(function (decrypt) {
      t.equals(decrypt.toString(), 'node encrypt, we decrypt');
    }).catch(function (e) {
      t.error(e||'error');
    });
  });
});
