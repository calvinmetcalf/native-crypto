'use strict';
const aes = require('browserify-aes');
const debug = require('debug')('native-crypto:encrypt');
let check = null;
const ZERO_BUF = new Buffer(32);

ZERO_BUF.fill(0);
const iv = new Buffer(12);
iv.fill(0);
const subtle = global.crypto && global.crypto.subtle;

function checkNative() {

  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  }
  if (!subtle || !subtle.importKey || !subtle.encrypt) {
    return Promise.resolve(false);
  }
  if (check) {
    return check;
  }
  check = subtle.importKey('raw', ZERO_BUF.buffer, {
    name: 'AES-GCM'
  }, true, ['encrypt']).then(key =>
    subtle.encrypt({
      name: 'AES-GCM',
      iv: iv
    }, key, ZERO_BUF.buffer)
  ).then(function(res) {
    if (new Buffer(res).toString('base64') === 'zqdAPU1ga24HTsXTuvOdGHJgA8o3pip00aL1jnUGNY7R0whMmaqKn9q7PoPrKMFd') {
      debug('has working subtle crypto for aes-gcm');
      return true;
    } else {
      debug('encrypted incorectly');
      return false;
    }
  }, function(e) {
    debug(e && e.message);
    return false;
  });
  return check;
}
module.exports = encrypt;

function encrypt(key, iv, plainText, aad) {
  if (typeof plainText === 'string') {
    plainText = new Buffer(plainText);
  }

  return checkNative().then(res => {
    if (res) {
      let opts = {
        name: 'AES-GCM',
        iv: iv
      };
      if (aad) {
        opts.additionalData = aad.buffer;
      }
      return subtle.importKey('raw', key.buffer, {
        name: 'AES-GCM'
      }, true, ['encrypt']).then(key =>
        subtle.encrypt(opts, key, plainText)
      ).then(resp => new Buffer(resp));
    } else {
      let algo = getAlgo(key);
      let cipher = aes.createCipheriv(algo, key, iv);
      if (aad) {
        cipher.setAAD(aad);
      }
      let output = cipher.update(plainText);
      cipher.final();
      let tag = cipher.getAuthTag();
      return Buffer.concat([output, tag]);
    }
  });
}

function getAlgo(key) {
  switch (key.length) {
  case 16:
    return 'aes-128-gcm';
  case 24:
    return 'aes-192-gcm';
  case 32:
    return 'aes-256-gcm';
  default:
    throw new TypeError('invalid key size');
  }
}
