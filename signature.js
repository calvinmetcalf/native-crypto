'use strict';
const sign = require('browserify-sign');
const debug = require('debug')('native-crypto:signature');
const checked = new Map();
const normalize = require('./normalize');
const ZERO_BUF = new Buffer(16);
ZERO_BUF.fill(0);
const jwk2pem = require('jwk-to-pem');
const SIGN = Symbol('sign');
const VERIFY = Symbol('verify');
const KEY = {};
const asn1 = require('asn1.js');

const ecSig = asn1.define('signature', function () {
  this.seq().obj(this.key('r').int(), this.key('s').int());
});
function toDER (input) {
  var sliceLen = Math.floor(input.length / 2);
  var r = input.slice(0, sliceLen);
  var s = input.slice(sliceLen);

  // Pad values
  if (r[0] & 0x80) {
    r = Buffer.concat([new Buffer([0]), r]);
  }
  // Pad values
  if (s[0] & 0x80) {
    s = Buffer.concat([new Buffer([0]), s]);
  }

  var total = r.length + s.length + 4
  var res = [ 0x30, total, 0x02, r.length ]
  return Buffer.concat([new Buffer([ 0x30, total, 0x02, r.length ]), r, new Buffer([ 0x02, s.length ]), s]);
}
function fromDer(input) {
  var parsed = ecSig.decode(input, 'der');
  return Buffer.concat([new Buffer(parsed.r.toArray()), new Buffer(parsed.s.toArray())]);
}
function checkNative(type, algo, curve) {
  algo = normalize(algo);
  if (curve) {
    curve = normalize(curve);
  }
  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  } else {
    if (!global.crypto
       || !global.crypto.subtle
       || !global.crypto.subtle.importKey
       || !global.crypto.subtle.sign
       || !global.crypto.subtle.verify
    ) {
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
      opts.hash = {name: algo};
    }
    let signOpts = {
      name: type
    };
    if (curve) {
      signOpts.hash = {name: algo};
    }
    let prom = global.crypto.subtle.generateKey(opts,
      false,
      ['sign']
  ).then(key=>
      global.crypto.subtle.sign(signOpts, key.privateKey, ZERO_BUF)
    ).then(function () {
        debug(`has working sublte crypto for type: ${type} with digest ${algo} ${curve ? `with curve: ${curve}` : ''}`);
        return true;
      }, function (e) {
        debug(e.message);
        return false;
      });
    checked.set(algo, prom);
    return prom;
  }
}

class Signature {
  constructor(key, algo, otherKey){
    this.algo = normalize(algo);
    if (key.kty.toLowerCase() === 'rsa') {
      this.type = 'RSASSA-PKCS1-v1_5';
      this.curve = null;
    } else if (key.kty.toLowerCase() === 'ec') {
      this.type = 'ECDSA';
      this.curve = normalize(key.crv);
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
        if (this.other) {
          this.nodeCrypto = sign.createVerify((this.curve ? 'ecdsa-with-' : 'RSA-') + normalize(this.algo, true));
        } else {
          this.nodeCrypto = sign.createSign((this.curve ? 'ecdsa-with-' : 'RSA-') + normalize(this.algo, true));
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
          let out = this.nodeCrypto.sign(jwk2pem(key, {private: true}));
          if (this.curve) {
            return fromDer(out);
          }
          return out;
        } else if (sym === VERIFY) {
          return this.nodeCrypto.verify(jwk2pem(key), this.curve ? toDER(this.other) : this.other);
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
        signOpts.hash = {name: this.algo};
      } else {
        importOpts.hash = {name: this.algo};
      }

      return global.crypto.subtle.importKey('jwk', key, importOpts, true, [use]).then(key => {
        this.key = null;
        if (sym === SIGN) {
          return global.crypto.subtle.sign(signOpts, key, data).then(buf => {
            return new Buffer(buf);
          });
        } else if (sym === VERIFY) {
          return global.crypto.subtle.verify(signOpts, key, this.other, data);
        }
      }
      );
    });
  }
  sign() {
    return this._final(SIGN);
  }
  verify() {
    return this._final(VERIFY);
  }
  static generateKey(type, len, algo) {
    return global.crypto.subtle.generateKey({
          name: type,
          modulusLength: len,
          publicExponent: new Buffer([0x01, 0x00, 0x01]),
          hash: {name: algo}
      },
      true,
      ['sign', 'verify']).then(key => global.crypto.subtle.exportKey('jwk', key));
  }
}
module.exports = Signature;
