'use strict';

var publicEncrypt = require('public-encrypt');
var debug = require('debug')('native-crypto:rsa');
var RSA_PKCS1_OAEP_PADDING = 4;
var jwk2pem = require('jwk-to-pem');
var checked = false;
var subtle = global.crypto && global.crypto.subtle;
var PUB_EXPONENT = new Buffer([0x01, 0x00, 0x01]);
function checkNative() {
  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  }
  if (!subtle || !subtle.importKey || !subtle.encrypt || !subtle.decrypt) {
    return Promise.resolve(false);
  }

  if (checked) {
    return checked;
  }

  var prom = subtle.generateKey({
    name: 'RSA-OAEP',
    modulusLength: 1024,
    publicExponent: PUB_EXPONENT,
    hash: { name: 'SHA-1' } }, false, ['encrypt', 'decrypt']).then(function (keyPair) {
    return subtle.encrypt({ name: 'RSA-OAEP' }, keyPair.publicKey, PUB_EXPONENT).then(function (cypher) {
      return subtle.decrypt({ name: 'RSA-OAEP' }, keyPair.privateKey, cypher);
    });
  }).then(function (result) {
    if (new Buffer(result).toString('hex') === '010001') {
      debug('has working rsa encryption');
      return true;
    }
    debug('does not match');
    return false;
  }).catch(function (e) {
    debug('does not have working rsa encryption');
    return false;
  });
  checked = prom;
  return prom;
}

exports.encrypt = encrypt;

function encrypt(key, data) {
  return checkNative().then(function (response) {
    if (response) {
      return subtle.importKey('jwk', key, {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-1' }
      }, false, ['encrypt']).then(function (key) {
        return subtle.encrypt({
          name: 'RSA-OAEP'
        }, key, data);
      }).then(function (resp) {
        return new Buffer(resp);
      });
    } else {
      return publicEncrypt.publicEncrypt(jwk2pem(key), data);
    }
  });
}
exports.decrypt = decrypt;

function decrypt(key, data) {
  return checkNative().then(function (response) {
    if (response) {
      return subtle.importKey('jwk', key, {
        name: 'RSA-OAEP',
        hash: { name: 'SHA-1' }
      }, false, ['decrypt']).then(function (key) {
        return subtle.decrypt({
          name: 'RSA-OAEP'
        }, key, data);
      }).then(function (resp) {
        return new Buffer(resp);
      });
    } else {
      return publicEncrypt.privateDecrypt(jwk2pem(key, {
        private: true
      }), data);
    }
  });
}