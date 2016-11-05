'use strict';
const createHash = require('create-hash');
const sign = require('browserify-sign');
const debug = require('debug')('native-crypto:signature');
const checked = new Map();
const normalize = require('./normalize');
const ZERO_BUF = new Buffer(16);
ZERO_BUF.fill(0);
const jwk2pem = require('jwk-to-pem');
const SIGN = Symbol('sign');
const VERIFY = Symbol('verify');
const base64url = require('./base64url');
const KEY = {};
let raw = null;
if (!process.browser) {
  raw = (function() {
    try {
      return require('raw-ecdsa');
    } catch (e) {
      return null;
    }
  }());
}
const elliptic = require('elliptic');
const EC = elliptic.ec
var format = require('ecdsa-sig-formatter');
var fromDer = format.derToJose;
var toDer = format.joseToDer;
var subtle = global.crypto && global.crypto.subtle;
function checkNative(type, algo, curve) {
  algo = normalize(algo);
  if (curve) {
    curve = normalize(curve);
  }
  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  }
  if (!subtle || !subtle.importKey || !subtle.sign || !subtle.verify) {
    return Promise.resolve(false);
  }
  var id = `${algo}-${type}-${curve}`;
  if (checked.has(id)) {
    return checked.get(id);
  }
  let opts = {
    name: type
  };
  if (curve) {
    opts.namedCurve = curve;
  } else {
    opts.modulusLength = 1024;
    opts.publicExponent = new Buffer([0x01, 0x00, 0x01]);
    opts.hash = {
      name: algo
    };
  }
  let signOpts = {
    name: type
  };
  if (curve) {
    signOpts.hash = {
      name: algo
    };
  }
  let prom = subtle.generateKey(opts,
    false, ['sign']
  ).then(key =>
    subtle.sign(signOpts, key.privateKey, ZERO_BUF)
  ).then(function() {
    debug(`has working sublte crypto for type: ${type} with digest ${algo} ${curve ? `
      with curve: ${curve}
      ` : ''}`);
    return true;
  }, function(e) {
    debug(e.message);
    return false;
  });
  checked.set(algo, prom);
  return prom;
}
var lens = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66
};
var ecNames = {
  'P-256': 'p256',
  'P-384': 'p384',
  'P-521': 'p521'
};
var otherECNames = {
  'P-256': 'ES256',
  'P-384': 'ES384',
  'P-521': 'ES512'
}
class Signature {
  constructor(key, otherKey) {
    if (key.kty && key.kty.toLowerCase() === 'rsa') {
      this.type = 'RSASSA-PKCS1-v1_5';
      this.curve = null;
    } else if (key.kty && key.kty.toLowerCase() === 'ec') {
      this.type = 'ECDSA';
      this.curve = normalize(key.crv);
    }
    if (this.curve) {
      switch (this.curve) {
      case 'P-256':
        this.algo = 'SHA-256';
        break;
      case 'P-384':
        this.algo = 'SHA-384';
        break;
      case 'P-521':
        this.algo = 'SHA-512';
        break;
      }
    } else if (key.alg) {
      this.algo = normalize(key.alg);
    } else {
      throw new Error('invalid key');
    }
    this._key = new WeakMap();
    this._key.set(KEY, key);
    if (otherKey) {
      this.other = otherKey;
    } else {
      this.other = false;
    }
    this.hasNative = void 0;
    this.checking = true;
    this._cache = [];
    this.nodeCrypto = null;
    this.check = checkNative(this.type, this.algo, this.curve).then(answer => {
      this.checking = false;
      if (answer) {
        this.hasNative = true;
      } else {
        this.hasNative = false;
        let algo = normalize(this.algo, true);
        if (this.curve) {
          this.nodeCrypto = createHash(algo);
        } else if (this.other) {
          this.nodeCrypto = sign.createVerify('RSA-' + algo);
        } else {
          this.nodeCrypto = sign.createSign('RSA-' + algo);
        }
        if (this._cache && this._cache.length) {
          this._cache.forEach(thing => {
            this.nodeCrypto.update(thing);
          });
          this._cache = null;
        }
      }
    });
  }
  update(data) {
    if (this.nodeCrypto) {
      this.nodeCrypto.update(data);
    } else if (this._cache) {
      this._cache.push(data);
    } else {
      throw new Error('should be imposible to get here');
    }
    return this;
  }
  _final(sym) {
    if (this.other) {
      if (sym !== VERIFY) {
        return Promise.reject(new Error('use verify method'));
      }
    } else {
      if (sym !== SIGN) {
        return Promise.reject(new Error('use digest method'));
      }
    }
    var use;
    if (sym === VERIFY) {
      use = 'verify';
    } else if (sym === SIGN) {
      use = 'sign';
    }
    return this.check.then(() => {
      let key = this._key.get(KEY);
      if (this.nodeCrypto) {
        if (sym === SIGN) {
          if (!this.curve) {
            return this.nodeCrypto.sign(jwk2pem(key, {
              private: true
            }));
          }
          let hash = this.nodeCrypto.digest();
          if (raw) {
            let signKey = new raw.Key(new Buffer(jwk2pem(key, {
              private: true
            })));
            return new Buffer(fromDer(signKey.sign(hash),  otherECNames[this.curve]), 'base64');
          }
          let ec = new EC(ecNames[this.curve]);
          let keyPair = ec.keyFromPrivate(base64url.decode(key.d));
          let sig = keyPair.sign(hash);
          let r = new Buffer(sig.r.toArray());
          let s = new Buffer(sig.s.toArray());
          let len = lens[this.curve];
          while (r.length < len) {
            r = Buffer.concat([new Buffer([0]), r]);
          }
          while (s.length < len) {
            s = Buffer.concat([new Buffer([0]), s]);
          }
          return Buffer.concat([r, s]);
        } else if (sym === VERIFY) {
          if (!this.curve) {
            return this.nodeCrypto.verify(jwk2pem(key), this.other);
          }
          let other = toDer(this.other, otherECNames[this.curve]);

          let hash = this.nodeCrypto.digest();
          if (raw) {
            let ver = new raw.Key(new Buffer(jwk2pem(key)));
            return ver.verify(other, hash);
          }
          let ec = new EC(ecNames[this.curve]);
          return ec.verify(hash, other, {
            x: base64url.decode(key.x).toString('hex'),
            y: base64url.decode(key.y).toString('hex')
          });
        }
      }
      var data;
      if (!this._cache.length) {
        data = new Buffer('');
      } else if (this._cache.length === 1) {
        data = this._cache[0];
      } else {
        data = Buffer.concat(this._cache);
      }
      let importOpts = {
        name: this.type
      };
      let signOpts = {
        name: this.type
      };
      if (this.curve) {
        importOpts.namedCurve = this.curve;
        signOpts.hash = {
          name: this.algo
        };
      } else {
        importOpts.hash = {
          name: this.algo
        };
      }

      return subtle.importKey('jwk', key, importOpts, true, [use]).then(key => {
        this.key = null;
        if (sym === SIGN) {
          return subtle.sign(signOpts, key, data).then(buf => {
            return new Buffer(buf);
          });
        } else if (sym === VERIFY) {
          return subtle.verify(signOpts, key, this.other, data);
        }
      });
    });
  }
  sign() {
    return this._final(SIGN);
  }
  verify() {
    return this._final(VERIFY);
  }
  static generateKey(type, len, algo) {
    return subtle.generateKey({
      name: type,
      modulusLength: len,
      publicExponent: new Buffer([0x01, 0x00, 0x01]),
      hash: {
        name: algo
      }
    },
    true, ['sign', 'verify']).then(key => subtle.exportKey('jwk', key));
  }
}
module.exports = Signature;
