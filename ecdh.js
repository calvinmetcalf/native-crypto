'use strict';
var createECDH = require('create-ecdh');
const debug = require('debug')('native-crypto:ecdh');
const normalize = require('./normalize');
const checked = new Map();
const KEYS = {};
const jwk = require('./jwk');
const base64url = require('./base64url');
const secLens = new Map([
  ['P-256', 256],
  ['P-384', 384],
  ['P-521', 520]
]);

function checkNative(algo) {
  algo = normalize(algo);
  if (!process.browser) {
    return Promise.resolve(false);
  } else {
    if (!global.crypto
      || !global.crypto.subtle
      || !global.crypto.subtle.generateKey
      || !global.crypto.subtle.deriveBits) {
      return Promise.resolve(false);
    }
    if (checked.has(algo)) {
      return checked.get(algo);
    }
    let prom = Promise.all([global.crypto.subtle.generateKey({
      name: 'ecdh',
      namedCurve: algo
    }, true, ['deriveBits']), global.crypto.subtle.generateKey({
      name: 'ecdh',
      namedCurve: algo
    }, true, ['deriveBits'])]).then(resp=>{
      let pub1 = resp[0].publicKey;
      let pub2 = resp[1].publicKey;
      let priv1 = resp[0].privateKey;
      let priv2 = resp[1].privateKey;
      let outLen = secLens.get(algo);
      return Promise.all([
        global.crypto.subtle.deriveBits({
          name: 'ecdh',
          namedCurve: algo,
          public: pub1
        }, priv2, outLen),
        global.crypto.subtle.deriveBits({
          name: 'ecdh',
          namedCurve: algo,
          public: pub2
        }, priv1, outLen),
        global.crypto.subtle.exportKey('jwk', priv1)
      ]).then(resp=>{
        if (new Buffer(resp[0]).toString('base64') === new Buffer(resp[1]).toString('base64')) {
          debug(`has working ecdh with curve ${algo}`);
          return true;
        } else {
          debug(`results did not match for curve ${algo}`);
          return false;
        }
      }).catch(e=>{
        debug(`non working subtle crypto for curve ${algo} due to error ${e}`);
        return false;
      });
    });
    checked.set(algo, prom);
    return prom;
  }
}

class ECDH {
  constructor(curve, priv) {
    this.curve = normalize(curve);
    this.hasNative = void 0;
    this.checking = true;
    this._map = new WeakMap();
    this.check = checkNative(curve).then(answer => {
      this.checking = false;
      if (answer) {
        this.hasNative = true;
        let makeKeys;
        if (priv) {
          let pub = {};
          Object.keys(priv).forEach(key => {
            if (key !== 'd') {
              pub[key] = priv[key];
            }
          });
          makeKeys = Promise.all([global.crypto.subtle.importKey('jwk', priv, {
           name: 'ecdh',
           namedCurve: this.curve
         }, true, ['deriveBits']), global.crypto.subtle.importKey('jwk', pub, {
          name: 'ecdh',
          namedCurve: this.curve
        }, true, [])]).then(resp => {
          return {
            privateKey: resp[0],
            publicKey: resp[1]
          };
        });
        } else {
          makeKeys = global.crypto.subtle.generateKey({
            name: 'ecdh',
            namedCurve: this.curve
          }, true, ['deriveBits']);
        }
        return makeKeys.then(resp=>{
          this._map.set(KEYS, resp);
        });
      } else {
        this.hasNative = false;
        let nodeCrypto = createECDH(normalize(curve, true));
        nodeCrypto.generateKeys();
        this._map.set(KEYS, nodeCrypto);
        if (priv) {
          nodeCrypto.setPrivateKey(base64url.decode(priv.d));
          nodeCrypto.setPublicKey(jwk.fromJwk(priv));
        }
      }
    });
  }
  getPublic() {
    return this.check.then(()=>{
      let pair = this._map.get(KEYS);
      if (this.hasNative) {
        return global.crypto.subtle.exportKey('jwk', pair.publicKey);
      } else {
        return jwk.toJwk(pair.getPublicKey(), this.curve);
      }
    });
  }
  getPrivate() {
    return this.check.then(()=>{
      let pair = this._map.get(KEYS);
      if (this.hasNative) {
        return global.crypto.subtle.exportKey('jwk', pair.privateKey);
      } else {
        let out = jwk.toJwk(pair.getPublicKey(), this.curve);
        out.d = base64url.encode(pair.getPrivateKey());
        return out;
      }
    });
  }
  computeSecret(publicKey) {
    return this.check.then(()=>
      Promise.resolve(publicKey)
    ).then(publicKey => {
      let pair = this._map.get(KEYS);
      if (this.hasNative) {
        return global.crypto.subtle.importKey('jwk', publicKey, {
          name: 'ecdh',
          namedCurve: this.curve
        }, true, [])
        .then(key => global.crypto.subtle.deriveBits({
          name: 'ecdh',
          namedCurve: this.curve,
          public: key
        }, pair.privateKey, secLens.get(this.curve)))
        .then(res => new Buffer(res));
      } else {
        return pair.computeSecret(jwk.fromJwk(publicKey));
      }
    });
  }
}
module.exports = ECDH;
