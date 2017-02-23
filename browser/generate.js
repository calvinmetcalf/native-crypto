'use strict';

var normalize = require('./normalize');
var checks = new Map();
var debug = require('debug')('native-crypto:generate');
var createECDH = require('create-ecdh');
var base64url = require('./base64url');
var genRSA = require('./genrsa');
var jwk = require('./jwk');
var subtle = global.crypto && global.crypto.subtle;
module.exports = generate;
var curves = new Set(['P-521', 'P-384', 'P-256']);
var DEFAULT_MODLENGTH = 4096;
function generate(opts, len, exponent) {
  if (typeof opts === 'string') {
    opts = {
      type: opts
    };
  }
  var algo = normalize(opts.type);
  if (curves.has(algo)) {
    return generateECC(algo);
  }
  len = len || opts.modLength || DEFAULT_MODLENGTH;
  exponent = exponent || opts.exponent || new Buffer([1, 0, 1]);
  if (typeof exponent === 'number') {
    exponent = exponent.toString('16');
    if (exponent.length % 2) {
      exponent = '0' + exponent;
    }
    exponent = new Buffer(exponent, 'hex');
  } else if (!Buffer.isBuffer(exponent) && exponent.byteLength) {
    if (exponent.byteLength > 1) {
      exponent = new Buffer(exponent.buffer);
    } else {
      exponent = new Buffer(exponent);
    }
  }
  return generateRSA(opts.type, len, exponent);
}
function generateECC(type) {
  return checkEcc(type).then(function (working) {
    if (working) {
      if (Array.isArray(working)) {
        return working;
      }
      return subtle.generateKey({
        name: 'ECDSA',
        namedCurve: type
      }, true, ['sign', 'verify']).then(function (resp) {
        return Promise.all([subtle.exportKey('jwk', resp.publicKey), subtle.exportKey('jwk', resp.privateKey)]);
      }).then(function (resp) {
        return {
          publicKey: resp[0],
          privateKey: resp[1]
        };
      });
    }
    var pair = createECDH(normalize(type, true));
    pair.generateKeys();
    var publicKey = jwk.toJwk(pair.getPublicKey(), type);
    var privateKey = {
      kty: 'EC',
      crv: type,
      x: publicKey.x,
      y: publicKey.y,
      ext: true,
      d: base64url.encode(pair.getPrivateKey())
    };
    return {
      publicKey: publicKey,
      privateKey: privateKey
    };
  });
}
function checkEcc(type) {
  if (subtle === undefined || !subtle.generateKey || !subtle.sign || !subtle.verify || !subtle.exportKey) {
    {
      debug('subtle crypto not supported');
    }
    return Promise.resolve(false);
  }
  if (checks.has(type)) {
    return checks.get(type);
  }
  var prom = subtle.generateKey({
    name: 'ECDSA',
    namedCurve: type
  }, true, ['sign', 'verify']).then(function (resp) {
    return Promise.all([subtle.exportKey('jwk', resp.publicKey), subtle.exportKey('jwk', resp.privateKey)]);
  }).then(function (resp) {
    debug('can generate ecc keys for curve ' + type);
    return {
      publicKey: resp[0],
      privateKey: resp[1]
    };
  }).catch(function (e) {
    debug('can\'t generate ecc keys for curve ' + type + ' due to ' + e);
    return false;
  });
  checks.set(type, prom.then(function () {
    return true;
  }));
  return prom;
}
function checkRsa(algo, len, exponent) {
  if (subtle === undefined || !subtle.generateKey || !subtle.sign || !subtle.verify || !subtle.exportKey) {
    {
      debug('subtle crypto not supported');
    }
    return Promise.resolve(false);
  }
  var type = algo + '-' + len + '-' + exponent.toString('hex');
  if (checks.has(type)) {
    return checks.get(type);
  }
  var prom = subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: len,
    publicExponent: exponent,
    hash: { name: algo }
  }, true, ['sign', 'verify']).then(function (resp) {
    return Promise.all([subtle.exportKey('jwk', resp.publicKey), subtle.exportKey('jwk', resp.privateKey)]);
  }).then(function (resp) {
    debug('can generate rsa keys for algo: ' + algo + ', len: ' + len + ', exponent: ' + exponent.toString('hex'));
    return {
      publicKey: resp[0],
      privateKey: resp[1]
    };
  }).catch(function (e) {
    debug('can\'t generate rsa keys for algo: ' + algo + ', len: ' + len + ', exponent: ' + exponent.toString('hex'));
    return false;
  });
  checks.set(type, prom.then(function (resp) {
    return !!resp;
  }));
  return prom;
}
function generateRSA(algo, len, exponent) {
  var type = normalize(algo);
  return checkRsa(type, len, exponent).then(function (check) {
    if (check) {
      if (Array.isArray(check)) {
        return check;
      }
      return subtle.generateKey({
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: len,
        publicExponent: exponent,
        hash: { name: type }
      }, true, ['sign', 'verify']).then(function (resp) {
        return Promise.all([subtle.exportKey('jwk', resp.publicKey), subtle.exportKey('jwk', resp.privateKey)]);
      }).then(function (resp) {
        return {
          publicKey: resp[0],
          privateKey: resp[1]
        };
      });
    }
    return genRSA(len, exponent).then(function (pair) {
      pair.publicKey.alg = algo.toUpperCase();
      pair.privateKey.alg = algo.toUpperCase();
      return pair;
    });
  });
}