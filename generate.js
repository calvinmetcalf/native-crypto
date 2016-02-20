'use strict';
const normalize = require('./normalize');
const checks = new Map();
const debug = require('debug')('native-crypto:pbkdf2');
const createECDH = require('create-ecdh');
const base64url = require('./base64url');
const jwk = require('./jwk');
const subtle = global.crypto && global.crypto.subtle;
module.exports = generate;
const curves = new Set(['P-521', 'P-384', 'P-256']);
const DEFAULT_EXPONENT = new Buffer([1, 0, 1]);
const DEFAULT_MODLENGTH = 4096;
function generate(opts, len) {
  if (typeof opts === 'string') {
    opts = {
      type: opts
    };
  }
  const type = normalize(opts.type);
  if (curves.has(type)) {
    return generateECC(type);
  }
  len = len || opts.modLength || DEFAULT_MODLENGTH;
  const exponent = opts.exponent || DEFAULT_EXPONENT;
  return generateRSA(type, len, exponent);
}
function generateECC(type) {
  return checkEcc(type).then(function (working) {
    if (working) {
      return subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: type
        },
        false,
        ['sign', 'verify'])
        .then(function (resp) {
          return Promise.all([
            subtle.exportKey('jwk', resp.publicKey),
            subtle.exportKey('jwk', resp.privateKey)
          ]);
        }).then(function (resp){
          return {
            publicKey: resp[0],
            privateKey: resp[1];
          }
        });
      }
      const pair = createECDH(normalize(type, true));
      pair.generateKeys();
      var publicKey = jwk.toJwk(pair.getPublicKey(), type);
      var privateKey = {
        kty: 'EC',
        crv: type,
        x: publicKey.x,
        y: publicKey.y,
        ext: true,
        d: base64url.encode(pair.getPrivateKey());
      };
      return {
        publicKey,
        privateKey
      }
  });
}
function checkEcc(type) {
  if (!process.browser || !subtle || !subtle.generateKey || !sublte.sign || !subtle.verify || !sublte.exportKey) {
    return Promise.resolve(false);
  }
  if (check.has(type)) {
    return check.get(type);
  }
  const prom = subtle.generateKey(
    {
        name: 'ECDSA',
        namedCurve: type
    },
    false,
    ['sign', 'verify'])
  .then(function (resp) {
    return Promise.all([
      subtle.exportKey('jwk', resp.publicKey),
      subtle.exportKey('jwk', resp.privateKey)
    ]);
  }).then(function () {
    debug(`can generate ecc keys for curve ${type}`);
    return true;
  }).catch(function (e) {
    debug(`can't generate ecc keys for curve ${type} due to ${e}`);
    return false;
  });
  check.set(type, prom);
  return prom;
}
