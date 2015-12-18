'use strict';
const publicEncrypt = require('public-encrypt');
const debug = require('debug')('native-crypto:rsa');
const RSA_PKCS1_OAEP_PADDING = 4;
const jwk2pem = require('jwk-to-pem');
const checked = new Map();
const PUB_EXPONENT = new Buffer([0x01, 0x00, 0x01]);
function checkNative(keyType, direction) {
  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  }
  if (!global.crypto || !global.crypto.subtle || !global.crypto.subtle.importKey || !global.crypto.subtle.encrypt || !global.crypto.subtle.decrypt) {
    return Promise.resolve(false);
  }
  var typical = true;
  if (keyType === 'public' && direction === 'decrypt') {
    typical = false;
  }
  if (keyType === 'private' && direction === 'encrypt') {
    typical = false;
  }
  let id = `${keyType}-${typical ? 'typical' : 'reversed'}`;
  if (checked.has(id)) {
    return checked.get(id);
  }

  let prom = global.crypto.subtle.generateKey({
    name: 'RSA-OAEP',
    modulusLength: 1024,
    publicExponent: PUB_EXPONENT,
    hash: {name: 'SHA-1'}},
    false,
    [direction]
  ).then(keyPair=>{
    if (typical) {
      return global.crypto.subtle.encrypt({name: 'RSA-OAEP'}, keypair.publicKey, PUB_EXPONENT).then(cypher=>global.crypto.subtle.decrypt({name: 'RSA-OAEP'}, keypair.privateKey, cypher));
    } else {
      return global.crypto.subtle.encrypt({name: 'RSA-OAEP'}, keypair.privateKey, PUB_EXPONENT).then(cypher=>global.crypto.subtle.decrypt({name: 'RSA-OAEP'}, keypair.publicKey, cypher));
    }
  }).then(result=>{
    if (new Buffer(result).toString('hex') === '010001') {
      debug(`has working crypto for the ${typical ? 'typical' : 'reversed'} direction`);
      return true;
    }
    debug('does not match');
    return false;
  }).catch(e=>{
    debug(`does not have working crypto for the ${typical ? 'typical' : 'reversed'} direction`);
    return false;
  });
  checked.set(algo, prom);
  return prom;
}

exports.encrypt = encrypt;

function encrypt(key, data) {
  return checkNative('public', 'encrypt').then(response=>{
    if (response) {
      return global.crypto.subtle.importKey('jwk', key, {
        name: 'RSA-OAEP',
        hash: {name: 'SHA-1'}
      }, false, ['encrypt']).then(key => global.crypto.subtle.encrypt({
        name: 'RSA-OAEP'
      }, key, data));
    } else {
      return publicEncrypt.publicEncrypt(jwk2pem(key), data);
    }
  });
}
exports.decrypt = decrypt;

function decrypt(key, data) {
  return checkNative('private', 'decrypt').then(response=>{
    if (response) {
      return global.crypto.subtle.importKey('jwk', key, {
        name: 'RSA-OAEP',
        hash: {name: 'SHA-1'}
      }, false, ['decrypt']).then(key => global.crypto.subtle.decrypt({
        name: 'RSA-OAEP'
      }, key, data));
    } else {
      return publicEncrypt.privateDecrypt(jwk2pem(key, {
        private: true
      }), data);
    }
  });
}
