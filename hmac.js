'use strict';
const createHmac = require('create-hmac');
const debug = require('debug')('native-crypto:hmac');
const checked = new Map();
const ZERO_BUF = new Buffer(8);
const normalize = require('./normalize');

const bufferEq = require('buffer-equal-constant-time');

ZERO_BUF.fill(0);
var SIGN = Symbol('sign');
var VERIFY = Symbol('verify');
function checkNative(algo) {
  algo = normalize(algo);
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
    if (checked.has(algo)) {
      return checked.get(algo);
    }
    let prom = global.crypto.subtle.importKey('raw', ZERO_BUF.buffer, {
      name: 'HMAC',
      hash: algo
    }, true, ['sign']).then(key=>
      global.crypto.subtle.sign('HMAC', key, ZERO_BUF.buffer)
    ).then(function () {
        debug('has working subtle crypto for ' + algo);
        return true;
      }, function (e) {
        debug(e.message);
        return false;
      });
    checked.set(algo, prom);
    return prom;
  }
}

class Hmac {
  constructor(algo, key, otherKey){
    this.algo = normalize(algo);
    this.key = key;
    if (otherKey) {
      this.other = otherKey;
    } else {
      this.other = false;
    }
    this.hasNative = void 0;
    this.checking = true;
    this._cache = [];
    this.nodeCrypto = null;
    this.check = checkNative(algo).then(answer => {
      this.checking = false;
      if (answer) {
        this.hasNative = true;
      } else {
        this.hasNative = false;
        this.nodeCrypto = createHmac(normalize(algo, true), key);
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
      if (this.nodeCrypto) {
          let out = this.nodeCrypto.digest();
          if (sym === SIGN) {
            return out;
          } else if (sym === VERIFY) {
            return bufferEq(out, this.other);
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
      return global.crypto.subtle.importKey('raw', this.key.buffer, {
        name: 'HMAC',
        hash: algo
      }, true, [use]).then(key => {
          this.key = null;
          if (sym === SIGN) {
            return global.crypto.subtle.sign('HMAC', key, data.buffer).then(buf => {
              return new Buffer(buf);
            });
          } else if (sym === VERIFY) {
            return global.crypto.subtle.sign('HMAC', key, this.other.buffer, data.buffer);
          }
        }
      );
    });
  }
  digest() {
    return this._final(SIGN);
  }
  verify() {
    return this._final(VERIFY);
  }
}
module.exports = Hmac;
