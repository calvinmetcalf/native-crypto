'use strict';
const createHash = require('create-hash');
const normalize = require('./normalize');
const debug = require('debug')('native-crypto:hash');
const checked = new Map();
const ZERO_BUF = new Buffer(8);
const subtle = global.crypto && global.crypto.subtle;
ZERO_BUF.fill(0);

function checkNative(algo) {
  algo = normalize(algo);
  if (!process.browser) {
    return Promise.resolve(false);
  }
  if (!subtle || !subtle.digest) {
    return Promise.resolve(false);
  }
  if (checked.has(algo)) {
    return checked.get(algo);
  }
  let prom = subtle.digest(algo, ZERO_BUF)
    .then(function() {
      debug('has working subtle crypto for ' + algo);
      return true;
    }, function() {
      return false;
    });
  checked.set(algo, prom);
  return prom;
}

class Hash {
  constructor(algo) {
    this.algo = normalize(algo);
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
        this.nodeCrypto = createHash(normalize(algo, true));
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
  digest() {
    return this.check.then(() => {
      if (this.nodeCrypto) {
        let out = this.nodeCrypto.digest();
        return out;
      }
      var data;
      if (!this._cache.length) {
        data = new Buffer('');
      } else if (this._cache.length === 1) {
        data = this._cache[0];
      } else {
        data = Buffer.concat(this._cache);
      }
      return subtle.digest(this.algo, data).then(buf =>
        new Buffer(buf)
      );
    });
  }
}
module.exports = Hash;
