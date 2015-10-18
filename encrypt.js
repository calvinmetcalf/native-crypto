'use strict';
const aes = require('browserify-aes')
const debug = require('debug')('native-crypto:hmac');
let check = null;
const ZERO_BUF = new Buffer(32);
const normalize = require('./normalize');

const bufferEq = require('buffer-equal-constant-time');
ZERO_BUF.fill(0);
const iv = new Buffer(12);
iv.fill(0);
function checkNative() {

  if (global.process && !global.process.browser) {
    return Promise.resolve(false);
  } else {
    if (!global.crypto
       || !global.crypto.subtle
       || !global.crypto.subtle.importKey
       || !global.crypto.subtle.encrypt
    ) {
        return Promise.resolve(false);
    }
    if (check) {
      return check;
    }
    check = global.crypto.subtle.importKey('raw', ZERO_BUF.buffer, {
      name: 'AES-GCM'
    }, true, ['encrypt']).then(key=>
      global.crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv: iv
      }, key, ZERO_BUF.buffer)
    ).then(function () {
        debug('has working subtle crypto for ' + algo);
        return true;
      }, function (e) {
        debug(e.message);
        return false;
      });
    return check;
  }
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
        opts.aad = aad.buffer;
      }
      return global.crypto.subtle.importKey('raw', key.buffer, {
        name: 'AES-GCM'
      }, true, ['encrypt']).then(key=>
        global.crypto.subtle.encrypt(opts, key, plainText)
      ).then(resp => new Buffer(resp));
    }
  });
}
